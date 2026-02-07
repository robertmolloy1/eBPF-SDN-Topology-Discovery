#!/usr/bin/env python
from core import eBPFCoreApplication, set_event_handler, PIPELINE
from core.packets import *

import cmd

import struct
import time
from threading import Thread
from twisted.internet import reactor
from scapy.all import Ether
from scapy.contrib.lldp import LLDPDUChassisID, LLDPDUPortID, LLDPDUTimeToLive, LLDPDUGenericOrganisationSpecific, LLDPDUEndOfLLDPDU

class MainCLI(cmd.Cmd):
    def __init__(self, application):
        cmd.Cmd.__init__(self)
        self.application = application

    # Start topology discovery process
    def do_discover_topology(self, line):
        if self.application.discovery_thread and self.application.discovery_thread.is_alive():
            print("Discovery process already running")
            return

        lldp_thread = Thread(target=self.application.lldp_generator)
        self.application.discovery_thread = lldp_thread
        self.application.threads.append(lldp_thread)

        link_remover_thread = Thread(target=self.application.link_remover)
        self.application.link_remover_thread = link_remover_thread
        self.application.threads.append(link_remover_thread)

        lldp_thread.start()
        link_remover_thread.start()
        print("Discovery process started")

    # Print out current internal representation of topology
    def do_print_topology(self,line):
        for src_sw in self.application.connections:
            for src_port, (dst_sw,dst_port,_time) in self.application.links[src_sw].items():
                print(f'Link: Switch {src_sw}, port {src_port} ---> switch {dst_sw}, port {dst_port}')

        for host,(switch,connected_port) in self.application.hosts.items():
            print(f'Host {host.hex(":")} connected to switch {switch}, port {connected_port}')

class TopologyDiscoveryApplication(eBPFCoreApplication):

    def __init__(self, *args, **kwargs):
        super().__init__(*args,**kwargs)
        self.active = True

        self.links = {}                       # Discovered switch to switch links (may contain one or two entries per link).   {src_sw : {src_port : (dst_sw,dst_port,timestamp)}}
        self.switch_to_switch_ports = {}      # Ports involved in switch to switch links (Always contains both sides of a link).   {(src_sw,src_port) : (dst_sw,dst_port)}
        self.hosts = {}                       # Discovered hosts, mapped to the switch and port they are connected to. {host : (switch,port)}
        self.switch_last_cycle_response = {}  # Maps a switch to the last discovery cycle they responded to.   {switch : cycle_id}

        self.threads = []
        self.discovery_thread = None
        self.link_remover_thread = None
        self.cycle_id = 0                     # ID of the current discovery cycle
        self.temporary_send_pool = {}         # Switches that temporarily have LLDP probes sent to them. Used when network is disconnected and some switches are not responding.
        self.permanent_send_pool = []         # Switches that will always have LLDP probes sent to them.

    def run(self):
        Thread(target=reactor.run, kwargs={'installSignalHandlers': 0}).start()

        try:
            MainCLI(self).cmdloop()
        except KeyboardInterrupt:
            print("\nGot keyboard interrupt. Exiting...")
        finally:
            self.active = False
            reactor.callFromThread(reactor.stop)
            for t in self.threads:
                t.join(timeout=5)

    @set_event_handler(Header.HELLO)
    def hello(self, connection, pkt):
        self.switch_last_cycle_response[connection.dpid] = 0
        self.links[connection.dpid] = {}
        print(connection.dpid)

        # Install eBPF functions
        with open('../topology_discovery/Topology_Discovery_v2.o', 'rb') as f:
            print("Installing the topology discovery eBPF ELF")
            connection.send(FunctionAddRequest(name="topologydiscovery", index=0, elf=f.read()))

        with open('../examples/learningswitch.o', 'rb') as f:
            print("Installing the learning switch eBPF ELF")
            connection.send(FunctionAddRequest(name="learningswitch", index=1, elf=f.read()))

        print()

    @set_event_handler(Header.NOTIFY)
    def notify_event(self, connection, pkt):
        if pkt.id == 0: # Host discovery information
            self.host_discovery(connection,pkt)
        elif pkt.id == 1: # LLDP packet
            self.receive_lldp(connection,pkt)

    def host_discovery(self, connection, pkt):
        mac, port = struct.unpack("<6s2xI",pkt.data)
        switch = connection.dpid

        if (switch,port) in self.switch_to_switch_ports:
            # switch to switch link
            return
        
        self.hosts[mac] = (switch,port)

    @set_event_handler(Header.PACKET_IN)
    def receive_lldp(self, connection, pkt):
        metadatahdr_fmt = 'I10x'
        ethhdr_fmt = '>6s6sH'

        dst_port, = struct.unpack_from(metadatahdr_fmt, pkt.data, 0)
        eth_dst, eth_src, eth_type = struct.unpack_from(ethhdr_fmt, pkt.data, struct.calcsize(metadatahdr_fmt))
        dst_dpid = connection.dpid

        if eth_type != 0x88cc: # Ensure packet is LLDP
            return
        
        # Parse TLVs
        tlvs = []
        i = struct.calcsize(metadatahdr_fmt) + struct.calcsize(ethhdr_fmt)
        while i + 2 <= len(pkt.data):
            type_length, = struct.unpack_from(">H", pkt.data, i)
            if type_length == 0:
                break

            i+=2

            tlv_type = (type_length >> 9) & 0x7F
            tlv_length = type_length & 0x1FF

            tlv_value = pkt.data[i:i+tlv_length]
            i+=tlv_length

            tlvs.append((tlv_type,tlv_length,tlv_value))

        src_dpid = None 
        src_port = None
        cycle_id = None

        for tlv in tlvs:
            if tlv[0] == 1: # Chassis ID
                src_dpid = int.from_bytes(tlv[2][1:], "big")
            elif tlv[0] == 2: # Port ID
                src_port = int.from_bytes(tlv[2][1:], "big")
            elif tlv[0] == 127: # Custom
                subtype = int.from_bytes(tlv[2][3:4], "big")
                if subtype == 1: # Cycle ID
                    cycle_id = int.from_bytes(tlv[2][4:], "big")
            else:
                continue

        if src_dpid == None or src_port == None or cycle_id == None:
            return
        
        # If host was connected to this port, remove
        hosts_to_delete = []

        for host,(switch,connected_port) in self.hosts.items():
            if (src_dpid == switch and src_port == connected_port) or (dst_dpid == switch and dst_port == connected_port):
                hosts_to_delete.append(host)
        
        for host in hosts_to_delete:
            del self.hosts[host]
        
        time_now = time.time()
        self.links.setdefault(src_dpid, {})[src_port] = (dst_dpid,dst_port,time_now) # Add link
        self.switch_to_switch_ports[(src_dpid,src_port)] = (dst_dpid,dst_port) # Add both ports associated with link as switch to switch ports
        self.switch_to_switch_ports[(dst_dpid,dst_port)] = (src_dpid,src_port)
        self.switch_last_cycle_response[dst_dpid] = cycle_id # Update last cycle id resopnse for this switch

    # Send LLDP probes to specified switches
    def lldp_generator(self):
        LLDP_DST = "01:80:c2:00:00:0e"
        packet_start = (
            Ether(dst=LLDP_DST, src=LLDP_DST, type=0x88cc)
            /    LLDPDUChassisID(subtype=7, id=struct.pack(">Q",1))
            /    LLDPDUPortID(subtype=7, id=struct.pack("B",1))
            /    LLDPDUTimeToLive(ttl=120)
        )
        packet_end = LLDPDUEndOfLLDPDU()
        metadata_padding = b"\x00" * 14

        self.permanent_send_pool = [1]
        
        while self.active:
            self.cycle_id = (self.cycle_id + 1) % 256
            lldp_packet = metadata_padding + bytes(packet_start 
                                                   / LLDPDUGenericOrganisationSpecific(org_code=0x001122, subtype=1, data=struct.pack("B",self.cycle_id))
                                                   / packet_end)
            
            for switch in self.permanent_send_pool:
                self.connections[switch].send(PacketOut(data=lldp_packet , out_port=PIPELINE))
                self.switch_last_cycle_response[switch] = self.cycle_id

            for switch in self.temporary_send_pool:
                self.connections[switch].send(PacketOut(data=lldp_packet , out_port=PIPELINE))
                self.switch_last_cycle_response[switch] = self.cycle_id

            time.sleep(5)

    def link_remover(self):
        def maps_to(entry, neighbour_sw, neighbour_port):
            return entry is not None and entry[0] == neighbour_sw and entry[1] == neighbour_port

        # Loop to remove old links
        while self.active:
            time_now = time.time()
            links_to_delete = []
            for src_switch in self.connections:
                # If switch has been in temporary send pool for too long, remove
                if (src_switch in self.temporary_send_pool):
                    if (self.cycle_id - self.temporary_send_pool[src_switch] % 256 >= 10):
                        del self.temporary_send_pool[src_switch]

                # If switch has not responded to LLDP in 2 cycles (e.g. unreachable due to link failure), add to temporary send pool
                if (self.cycle_id - self.switch_last_cycle_response[src_switch] % 256 >= 2):
                    self.temporary_send_pool[src_switch]=self.cycle_id

                # Loop over links for switch and check for timeout
                for src_port, (dst_switch,dst_port,timestamp) in self.links[src_switch].items():
                    if time_now - timestamp >10:
                        links_to_delete.append((src_switch,src_port,dst_switch,dst_port))

            # Remove links flagged as timed out
            for src_switch,src_port,dst_switch,dst_port in links_to_delete:
                del self.links[src_switch][src_port]

                # For each port associated with this link, determine if it is still in a switch to switch link before removing:
                #     - Check if the forward link exists
                #     - Check if the backwards link exists
                #     - Check if the port is associated with a different link

                src_link_entry = self.links.get(src_switch, {}).get(src_port)
                dst_link_entry = self.links.get(dst_switch, {}).get(dst_port)

                if (src_link_entry is None
                    and (dst_link_entry is None or not maps_to(dst_link_entry, src_switch, src_port))
                    and maps_to(self.switch_to_switch_ports.get((src_switch,src_port)), dst_switch, dst_port)):

                    del self.switch_to_switch_ports[(src_switch,src_port)]

                if (dst_link_entry is None 
                    and (src_link_entry is None or not maps_to(src_link_entry, dst_switch, dst_port)) 
                    and maps_to(self.switch_to_switch_ports.get((dst_switch,dst_port)), src_switch, src_port)):

                    del self.switch_to_switch_ports[(dst_switch,dst_port)]

            time.sleep(5)

if __name__ == '__main__':
    TopologyDiscoveryApplication().run()