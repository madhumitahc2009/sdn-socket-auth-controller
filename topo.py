import os
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def create_topology():
    net = Mininet(switch=OVSSwitch, build=False, autoSetMacs=True)

    info('*** Adding Switch\n')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')

    info('*** Adding Hosts\n')
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    auth = net.addHost('auth', ip='10.0.0.10/24')
    target = net.addHost('target', ip='10.0.0.20/24')

    info('*** Creating Links\n')
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(auth, s1)
    net.addLink(target, s1)

    info('*** Starting Network\n')
    net.build()
    s1.start([])

    info('*** Installing Baseline OpenFlow Rules\n')
    os.system("ovs-ofctl -O OpenFlow13 del-flows s1")
    os.system("ovs-ofctl -O OpenFlow13 add-flow s1 priority=10,arp,actions=normal")
    os.system("ovs-ofctl -O OpenFlow13 add-flow s1 priority=50,ip,tcp,tp_dst=9000,actions=normal")
    os.system("ovs-ofctl -O OpenFlow13 add-flow s1 priority=50,ip,tcp,tp_src=9000,actions=normal")
    os.system("ovs-ofctl -O OpenFlow13 add-flow s1 priority=50,ip,tcp,tp_dst=5000,actions=normal")
    os.system("ovs-ofctl -O OpenFlow13 add-flow s1 priority=50,ip,tcp,tp_src=5000,actions=normal")
    os.system("ovs-ofctl -O OpenFlow13 add-flow s1 priority=0,actions=drop")

    info('*** Network Ready. Entering CLI.\n')
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()
