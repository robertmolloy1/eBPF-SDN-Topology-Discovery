#!/usr/bin/python
from mininet.net import Mininet
from mininet.topolib import TreeTopo
from mininet.node import UserSwitch
# from mininet.node import CPULimitedHost, Host, Node
#from mininet.node import OVSKernelSwitch, UserSwitch
#from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call
import time 
import sys

from eBPFSwitch import eBPFSwitch, eBPFHost

if len(sys.argv) != 3:
    print("Usage: learningswitch.py [depth] [fanout]")
    exit()

depth = int(sys.argv[1])
fanout = int(sys.argv[2])

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

switches.append(net.addSwitch('s1', dpid=1, switch_path=switchPath))

switch_counter = 2
parent_counter = 0

for i in range(1,depth):
    for j in range(fanout**(i-1)):
        for k in range(fanout):
            switches.append(net.addSwitch('s'+str(switch_counter), dpid=switch_counter, switch_path=switchPath))
            net.addLink(switches[parent_counter], switches[-1])
            print(f's{switch_counter}')
            switch_counter = switch_counter + 1
        
        parent_counter = parent_counter + 1

host_counter = 1

for i in range(fanout**(depth-1)):
    for j in range(fanout):
        hosts.append(net.addHost('h'+str(host_counter), cls=eBPFHost, ip='1.1.1.'+str(host_counter), defaultRoute='1.1.1.1',mac=':'.join(f'{host_counter:012x}'[i:i+2] for i in range(0,12,2))))
        net.addLink(switches[parent_counter], hosts[-1])
        print(f'h{host_counter}')
        host_counter = host_counter + 1

    parent_counter = parent_counter + 1

net.build()
info( '*** Starting controllers\n')
for controller in net.controllers:
    controller.start()

info( '*** Starting networking devices\n')
for i in range(1,len(switches)+1):
    net.get('s'+str(i)).start([])

for n in net.hosts + net.switches:
    n.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null')
    n.cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null')
    n.cmd('sysctl -w net.ipv6.conf.lo.disable_ipv6=1 >/dev/null')

CLI(net)
net.stop()