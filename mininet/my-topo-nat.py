#!/usr/bin/python

#  Copyright 2019-present Open Networking Foundation
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import argparse, time, threading

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Host
from mininet.link import Intf
from mininet.topo import Topo
from stratum import StratumBmv2Switch

CPU_PORT = 255

# Perform ARP Request for the gateway every 30 sec
def scheduleARP(host, gw):
    while(True):
        time.sleep(30)
        try:
            host.cmd('arping -c 1 %s &> /dev/null &' % gw)
        except Exception:
            pass

def scheduleARP_NAT(nat, intf, ip):
    while(True):
        time.sleep(30)
        try:
            nat.cmd('arping -P -i %s -U %s &> /dev/null &' % (intf, ip))
        except Exception:
            pass

class IPv4Host(Host):
    """Host that can be configured with an IPv4 gateway (default route).
    """


    def config(self, mac=None, ip=None, defaultRoute=None, lo='up', gw=None,
               **_params):
        super(IPv4Host, self).config(mac, ip, defaultRoute, lo, **_params)
        self.cmd('ip -4 addr flush dev %s' % self.defaultIntf())
        self.cmd('ip -6 addr flush dev %s' % self.defaultIntf())
        self.cmd('ip -4 link set up %s' % self.defaultIntf())
        self.cmd('ip -4 addr add %s dev %s' % (ip, self.defaultIntf()))
        if gw:
            self.cmd('ip -4 route add default via %s' % gw)
            threading.Thread(target=scheduleARP, args=(self, gw,)).start() #make non-blocking

        # Disable offload
        for attr in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload %s %s off" % (
                self.defaultIntf(), attr)
            self.cmd(cmd)



        def updateIP():
            return ip.split('/')[0]

        self.defaultIntf().updateIP = updateIP


class TutorialTopo(Topo):
    """2x2 fabric topology with IPv4 hosts"""

    def __init__(self, *args, **kwargs):
        Topo.__init__(self, *args, **kwargs)

        # Leaves
        # gRPC port 50001
        leaf1 = self.addSwitch('leaf1', cls=StratumBmv2Switch, cpuport=CPU_PORT)

        # IPv4 hosts attached to leaf 1
        h1 = self.addHost('h1', cls=IPv4Host, mac="00:00:00:00:00:10",
                           ip='10.0.0.1/16', gw='10.0.0.254')
    	
        self.addLink(h1, leaf1)  # port 1



def addNAT(net):
    """Custom node with dedicated interface and iptable rules"""

    subnet = '10.0.0.0/16'
    inetIntf = 'eth1'
    inetIp = '172.16.100.2'
    lanIntf = ''
    lanIp = '10.0.0.254'

    nat = net.addHost('nat', mac="00:ff:00:00:00:01") #!
    # nat = net.addHost('nat')
    net.addLink('leaf1', nat)
    Intf(inetIntf, nat)
    
    lanIntf = nat.defaultIntf()

    # Configure lan interface
    nat.cmd('ip -4 addr flush dev %s' % lanIntf)
    nat.cmd('ip -6 addr flush dev %s' % lanIntf)
    nat.cmd('ip -4 link set up %s' % lanIntf)
    nat.cmd('ip addr add %s/16 dev %s' % (lanIp, lanIntf))

    # Configure inet interface
    nat.cmd('ip -4 addr flush dev %s' % inetIntf)
    nat.cmd('ip -6 addr flush dev %s' % inetIntf)
    nat.cmd('ip -4 link set up %s' % inetIntf)
    nat.cmd('ip addr add %s/24 dev %s' % (inetIp, inetIntf))

    # default route
    nat.cmd('ip route add default via 172.16.100.1 dev %s' % inetIntf)

    # periodic arp
    # threading.Thread(target=scheduleARP, args=(nat, "255.255.255.255 -i nat-eth0",)).start() #!
    threading.Thread(target=scheduleARP_NAT, args=(nat, nat.defaultIntf(), lanIp)).start()

    # Instruct the kernel to perform forwarding
    nat.cmd('sysctl net.ipv4.ip_forward=1' )

    # nat.cmd('sysctl net.ipv4.ip_forward=0') #!
    # Flush any currently active rules
    nat.cmd('iptables -F')
    nat.cmd('iptables -t nat -F')
    # Create default entries for unmatched traffic
    nat.cmd('iptables -P INPUT ACCEPT')
    nat.cmd('iptables -P OUTPUT ACCEPT')
    nat.cmd('iptables -P FORWARD DROP')

    # Install NAT rules
    nat.cmd('iptables -I FORWARD',
            '-i', nat.defaultIntf(), '-d', subnet, '-j DROP')
    nat.cmd('iptables -A FORWARD',
            '-i', nat.defaultIntf(), '-s', subnet, '-j ACCEPT')
    nat.cmd('iptables -A FORWARD',
            '-i', inetIntf, '-d', subnet, '-j ACCEPT')
    nat.cmd('iptables -t nat -A POSTROUTING',
            '-o', inetIntf, '-s', subnet, '-j MASQUERADE')

    # Disable offload
    for attr in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload %s %s off" % (
                nat.defaultIntf(), attr)
            nat.cmd(cmd)


def main():
    net = Mininet(topo=TutorialTopo(), controller=None)
    addNAT(net)
    net.start()
    CLI(net)
    net.stop()
    print '#' * 80
    print 'ATTENTION: Mininet was stopped! Perhaps accidentally?'
    print 'No worries, it will restart automatically in a few seconds...'
    print 'To access again the Mininet CLI, use `make mn-cli`'
    print 'To detach from the CLI (without stopping), press Ctrl-D'
    print 'To permanently quit Mininet, use `make stop`'
    print '#' * 80


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Mininet topology script for 2x2 fabric with stratum_bmv2 and IPv4 hosts')
    args = parser.parse_args()
    setLogLevel('info')

    main()
