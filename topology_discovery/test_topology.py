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

switchPath = "../../BPFabric/softswitch/softswitch"; 

hosts = []
switches = []

hosts.append(net.addHost('h1', cls=eBPFHost, ip='1.1.1.1', defaultRoute='1.1.1.2',mac='00:00:00:00:00:01'))
switches.append(net.addSwitch('s1', dpid=1, switch_path=switchPath))
net.addLink(hosts[0], switches[0])

for i in range(1,int(sys.argv[1])):
    print(i)
    hosts.append(net.addHost('h'+str(i+1), cls=eBPFHost, ip='1.1.1.'+str(i+1), defaultRoute='1.1.1.1',mac='00:00:00:00:00:'+f'{i+1:02d}'))
    switches.append(net.addSwitch('s'+str(i+1), dpid=i+1, switch_path=switchPath))
    net.addLink(hosts[i], switches[i])
    net.addLink(switches[i-1], switches[i])

net.build()
info( '*** Starting controllers\n')
for controller in net.controllers:
    controller.start()

info( '*** Starting networking devices\n')
for i in range(1,int(sys.argv[1])+1):
    net.get('s'+str(i)).start([])

for n in net.hosts + net.switches:
    n.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null')
    n.cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null')
    n.cmd('sysctl -w net.ipv6.conf.lo.disable_ipv6=1 >/dev/null')

CLI(net)
net.stop()