#!/usr/bin/env python
from core import eBPFCoreApplication, set_event_handler, FLOOD
from core.packets import *

import cmd
import json

import struct
import time
from threading import Thread
from twisted.internet import reactor
from scapy.all import Ether
from scapy.contrib.lldp import LLDPDUChassisID, LLDPDUPortID, LLDPDUTimeToLive, LLDPDUEndOfLLDPDU

class MainCLI(cmd.Cmd):
    def __init__(self, application):
        cmd.Cmd.__init__(self)
        self.application = application

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


    def do_print_topology(self,line):
        # print(self.application.links)
        for src_sw in self.application.connections:
            for src_port, (dst_sw,dst_port,_time) in self.application.links[src_sw].items():
                print(f'Link: Switch {src_sw}, port {src_port} ---> switch {dst_sw}, port {dst_port}')

        for host,(switch,connected_port) in self.application.hosts.items():
            print(f'Host {host.hex(":")} connected to switch {switch}, port {connected_port}')

    def do_evaluate_topology(self,line):
        ground_truth = None
        with open("../topology_discovery/topology_ground_truth.json", "r") as f:
            ground_truth = json.load(f)

        if ground_truth == None:
            print("Ground truth could not be read")
            return
        
        controller_topology = self.application.get_topology()

        true_sw, true_h, true_sw_e, true_h_e = self.extract_graph_info(ground_truth,True)
        cont_sw, cont_h, cont_sw_e, cont_h_e = self.extract_graph_info(controller_topology)

        switches_prec,switches_rec, switches_f1 = self.calculate_metrics(true_sw,cont_sw)
        hosts_prec,hosts_rec, hosts_f1 = self.calculate_metrics(true_h,cont_h)
        switch_edges_prec,switch_edges_rec, switch_edges_f1 = self.calculate_metrics(true_sw_e,cont_sw_e)
        host_edges_prec,host_edges_rec, host_edges_f1 = self.calculate_metrics(true_h_e,cont_h_e)

        print("Topology Discovery Evaluation:")
        print(f'Switch Stats - Precision: {switches_prec}, Recall: {switches_rec}, F1: {switches_f1}')
        print(f'Host Stats - Precision: {hosts_prec}, Recall: {hosts_rec}, F1: {hosts_f1}')
        print(f'Switch Edge Stats - Precision: {switch_edges_prec}, Recall: {switch_edges_rec}, F1: {switch_edges_f1}')
        print(f'Host Edge Stats - Precision: {host_edges_prec}, Recall: {host_edges_rec}, F1: {host_edges_f1}')


    def do_export_topology(self,line):
        controller_topology = self.application.get_topology(True)

        with open("../topology_discovery/controller_discovered_topology.json", "w") as f:
            json.dump(controller_topology, f, indent=2, sort_keys=True)

        print(f"Exported discovered topology as JSON to ../topology_discovery/controller_discovered_topology.json")

    def extract_graph_info(self,topology,dup_links=False):
        switches = set()
        hosts = set()
        switch_edges = set()
        host_edges = set()

        for node in topology.get("nodes", []):
            node_type = str(node["type"])
            if node_type == "switch":
                switches.add(str(node["name"]))
            elif node_type == "host":
                hosts.add(str(node["name"]))

        for edge in topology.get("edges", []):
            node_a = str(edge["source"])
            node_b = str(edge["destination"])

            if node_a in hosts:
                port = str(edge["dst_port"])
                host_edges.add(((node_b,port), node_a))
            elif node_b in hosts:
                port = str(edge["src_port"])
                host_edges.add(((node_a,port), node_b))
            else:
                port_a = str(edge["src_port"])
                port_b = str(edge["dst_port"])
                switch_edges.add(((node_a,port_a),(node_b,port_b)))
                if dup_links:
                    switch_edges.add(((node_b,port_b),(node_a,port_a)))

        return switches, hosts, switch_edges, host_edges
    
    def calculate_metrics(self, ground_truth, controller_data):
        tp = len(ground_truth & controller_data)
        fp = len(controller_data - ground_truth)
        fn = len(ground_truth - controller_data)

        precision = tp / (tp+fp) if (tp+fp) else 1.0
        recall = tp / (tp+fn) if (tp+fn) else 1.0
        f1 = (2*precision*recall)/(precision+recall) if (precision+recall) else 1.0

        return precision,recall,f1


class TopologyDiscoveryApplication(eBPFCoreApplication):

    def __init__(self, *args, **kwargs):
        super().__init__(*args,**kwargs)
        self.active = True

        self.switch_ports = {}
        self.links = {}
        self.hosts = {}

        self.threads = []
        self.discovery_thread = None
        self.link_remover_thread = None

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
        self.switch_ports[connection.dpid] = {}
        self.links[connection.dpid] = {}

        # Generate LLDP packet for each port in advance 
        LLDP_DST = "01:80:c2:00:00:0e"
        for i in range(pkt.port_count):
            pkt = (
                Ether(dst=LLDP_DST, src=LLDP_DST, type=0x88cc)
                /    LLDPDUChassisID(subtype=7, id=struct.pack(">Q",connection.dpid))
                /    LLDPDUPortID(subtype=7, id=str(i))
                /    LLDPDUTimeToLive(ttl=120)
                /    LLDPDUEndOfLLDPDU()
            )
            pkt_bytes = b"\x00" * 14 + bytes(pkt) # Pad beginning of packet as BPFabric expects 14 bytes of metadata 

            self.switch_ports[connection.dpid][i] = pkt_bytes

        # Install eBPF functions
        with open('../topology_discovery/Topology_Discovery_OFDP.o', 'rb') as f:
            print("Installing the topology discovery eBPF ELF")
            connection.send(FunctionAddRequest(name="topologydiscovery", index=0, elf=f.read()))

        with open('../examples/learningswitch.o', 'rb') as f:
            print("Installing the learning switch eBPF ELF")
            connection.send(FunctionAddRequest(name="learningswitch", index=1, elf=f.read()))

        print()

    @set_event_handler(Header.NOTIFY)
    def notify_event(self, connection, pkt):
        mac, port = struct.unpack("<6s2xI",pkt.data)
        switch = connection.dpid

        if switch not in self.links or port in self.links[switch]:
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

        if eth_type != 0x88cc:
            return
        
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

        for tlv in tlvs:
            if tlv[0] == 1:
                src_dpid = int.from_bytes(tlv[2][1:], "big")
            elif tlv[0] == 2:
                src_port = int(tlv[2][1:])
            else:
                continue

        if src_dpid == None or src_port == None:
            return
        
        hosts_to_delete = []

        for host,(switch,connected_port) in self.hosts.items():
            if (src_dpid == switch and src_port == connected_port) or (dst_dpid == switch and dst_port == connected_port):
                hosts_to_delete.append(host)
        
        for host in hosts_to_delete:
            del self.hosts[host]
        
        self.links.setdefault(src_dpid, {})[src_port] = (dst_dpid,dst_port,time.time())

    def lldp_generator(self):
        while self.active:
            for switch in self.connections:
                for port, lldp_packet in self.switch_ports[switch].items():
                    self.connections[switch].send(PacketOut(data=lldp_packet, out_port=port))

            time.sleep(5)

    def link_remover(self):
        while self.active:
            time_now = time.time()
            links_to_delete = []
            for switch in self.connections:
                for port, value in self.links[switch].items():
                    if time_now - value[2] >10:
                        links_to_delete.append((switch,port))

            for link in links_to_delete:
                del self.links[link[0]][link[1]]

            time.sleep(5)

    def get_topology(self,single_links = False):
        switches = list(map(lambda x: {"name": x, "type": "switch"},list(self.connections.keys())))
        hosts = list(map(lambda x: {"name": x.hex(":"), "type": "host"},list(self.hosts.keys())))

        switch_edges = []
        switch_edges_seen = set()

        for src_sw in self.connections:
            for src_p, (dst_sw,dst_p,_) in self.links[src_sw].items():
                a = (src_sw, src_p)
                b = (dst_sw, dst_p)

                if single_links:

                    key = tuple(sorted([a, b], key=lambda x: (str(x[0]), -1 if x[1] is None else int(x[1]))))

                    if key in switch_edges_seen:
                        continue
                    switch_edges_seen.add(key)

                switch_edges.append({
                    "source": src_sw,
                    "destination": dst_sw,
                    "src_port": src_p,
                    "dst_port": dst_p,
                    "type": "switch to switch edge"
                })

        host_edges = []
        host_edges_seen = set()

        for host, (sw,p) in self.hosts.items():
            if host in host_edges_seen:
                continue
            host_edges_seen.add(host)

            host_edges.append({
                "source": sw,
                "destination": host.hex(":"),
                "src_port": p,
                "type": "host to switch edge"
            })

        return {"nodes": switches + hosts, "edges" : switch_edges + host_edges}


if __name__ == '__main__':
    TopologyDiscoveryApplication().run()