#!/usr/bin/python
from mininet.net import Mininet
from mininet.topolib import TreeTopo
from mininet.node import UserSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call
import time 
import sys
import re
import json
import ipaddress

from eBPFSwitch import eBPFSwitch, eBPFHost

def eth_index(interface):
    eth_re = re.compile(r".*-eth(\d+)$")
    m = eth_re.match(interface)
    return int(m.group(1))

def export_topology(net):
    nodes = []
    seen_nodes = set()

    for s in net.switches:
        dpid = str(s.dpid)
        if dpid not in seen_nodes:
            nodes.append({"name" : dpid, "type": "switch"})
            seen_nodes.add(dpid)

    for h in net.hosts:
        mac = h.MAC()
        if mac not in seen_nodes:
            nodes.append({"name" : mac, "type":"host"})
            seen_nodes.add(mac)

    edges = []
    edges_seen = set()

    for link in net.links:
        i1, i2 = link.intf1, link.intf2
        n1, n2 = i1.node, i2.node

        name1 = None
        name2 = None
        if (hasattr(n1, "dpid")):
            name1 = str(n1.dpid)
        else:
            name1 = n1.MAC()

        if (hasattr(n2, "dpid")):
            name2 = str(n2.dpid)
        else:
            name2 = n2.MAC()

        port1 = None
        port2 = None
        if (hasattr(n1, "dpid")):
            port1 = eth_index(i1.name) - 1
        else:
            port1 = eth_index(i1.name)

        if (hasattr(n2, "dpid")):
            port2 = eth_index(i2.name) - 1
        else:
            port2 = eth_index(i2.name)

        # Key to prevent duplicate link entries
        a = (name1, port1)
        b = (name2, port2)
        key = tuple(sorted([a, b], key=lambda x: (str(x[0]), -1 if x[1] is None else int(x[1]))))
        
        if key in edges_seen:
            continue
        edges_seen.add(key)

        edges.append({
            "source": name1,
            "destination": name2,
            "src_port": port1,
            "dst_port": port2,
            # "id": f"{key[0][0]}:{key[0][1]}--{key[1][0]}:{key[1][1]}"
        })

    data = {
        "format": "graph-json",
        "nodes" : nodes,
        "edges": edges
    }

    with open("topology_ground_truth.json", "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)

    print(f"Exported topology as JSON to topology_ground_truth.json")

def host_ip(n):
    net = ipaddress.IPv4Network("10.0.0.0/24", strict=False)
    return str(net.network_address + (n % (net.num_addresses - 2) + 1))

if len(sys.argv) != 2:
    print("Usage: learningswitch.py [host_num]")
    exit()

net = Mininet(
    topo=None,
    switch=eBPFSwitch,
    host=eBPFHost,
    build=False,
    ipBase='1.0.0.0/8'
)

switchPath = "../softswitch/softswitch"; 

hosts = []
switches = []

hosts.append(net.addHost('h1', cls=eBPFHost, ip=host_ip(1), defaultRoute='1.1.1.2',mac='00:00:00:00:00:01'))
switches.append(net.addSwitch('s1', dpid=1, switch_path=switchPath))
net.addLink(hosts[0], switches[0])

for i in range(1,int(sys.argv[1])):
    print(i)
    hosts.append(net.addHost('h'+str(i+1), cls=eBPFHost, ip=host_ip(i+1), defaultRoute='1.1.1.1',mac=':'.join(f'{i+1:012x}'[j:j+2] for j in range(0,12,2))))
    switches.append(net.addSwitch('s'+str(i+1), dpid=i+1, switch_path=switchPath))
    net.addLink(hosts[i], switches[i])
    net.addLink(switches[i-1], switches[i])

net.build()

for n in net.hosts + net.switches:
    n.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null')
    n.cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null')
    n.cmd('sysctl -w net.ipv6.conf.lo.disable_ipv6=1 >/dev/null')

info( '*** Starting controllers\n')
for controller in net.controllers:
    controller.start()

info( '*** Starting networking devices\n')
for i in range(1,int(sys.argv[1])+1):
    net.get('s'+str(i)).start([])
    time.sleep(0.3)

export_topology(net)

CLI(net)
net.stop()