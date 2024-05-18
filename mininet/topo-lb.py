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

# Perform ARP Reply every 30 sec
def scheduleArpReply(host, intf, ip):
    while(True):
        time.sleep(30)
        try:
            host.cmd('arping -P -i %s -U %s -c 1 &> /dev/null &' % (intf, ip))
        except Exception:
            pass

class IPv4Host(Host):
    """Host without IPv4 gateway"""

    def config(self, mac=None, ip=None, defaultRoute=None, lo='up', gw=None,
               **_params):
        super(IPv4Host, self).config(mac, ip, defaultRoute, lo, **_params)
        self.cmd('ip -4 addr flush dev %s' % self.defaultIntf())
        self.cmd('ip -6 addr flush dev %s' % self.defaultIntf())
        self.cmd('ip -4 link set up %s' % self.defaultIntf())
        self.cmd('ip -4 addr add %s dev %s' % (ip, self.defaultIntf()))
        self.cmd('ip -4 route add default via %s' % gw)

        # self.cmd('sysctl net.ipv4.ip_forward=1' )

        threading.Thread(target=scheduleArpReply, args=(self, self.defaultIntf(), ip.split('/')[0],)).start() #make non-blocking

        # Disable offload
        for attr in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload %s %s off" % (
                self.defaultIntf(), attr)
            self.cmd(cmd)

        def updateIP():
            return ip.split('/')[0]

        self.defaultIntf().updateIP = updateIP

class IPv4Server(IPv4Host):

    def config(self, mac=None, ip=None, defaultRoute=None, lo='up', gw=None,
               **_params):
        super(IPv4Server, self).config(mac, ip, defaultRoute, lo, **_params)

        # Servers should start with dedicated script
        # self.cmd('python /mininet/server.py %s &' % self.name)

class TutorialTopo(Topo):
    """Simple topo please
    v1 - all in same subnet
    """

    def __init__(self, *args, **kwargs):
        Topo.__init__(self, *args, **kwargs)

        # Leaves
        # gRPC port 50001
        lb = self.addSwitch('lb1', cls=StratumBmv2Switch, cpuport=CPU_PORT)


        # IPv4 hosts attached to leaf 1
        h1 = self.addHost('h1', cls=IPv4Host, mac="00:00:00:00:00:10",
                           ip='10.0.1.1/16')
        self.addLink(h1, lb)  # port 1

        # IPv4 hosts attached to leaf 2
        server1 = self.addHost('server1', cls=IPv4Server, mac="00:00:00:00:10:10",
                          ip='10.0.10.1/16')
        server2 = self.addHost('server2', cls=IPv4Server, mac="00:00:00:00:20:10",
                          ip='10.0.20.1/16')
        server3 = self.addHost('server3', cls=IPv4Server, mac="00:00:00:00:30:10",
                          ip='10.0.30.1/16')
        server4 = self.addHost('server4', cls=IPv4Server, mac="00:00:00:00:40:10",
                          ip='10.0.40.1/16')
        self.addLink(server1, lb)  # port 2
        self.addLink(server2, lb)  # port 3
        self.addLink(server3, lb)  # port 4
        self.addLink(server4, lb)  # port 5


def main():
    net = Mininet(topo=TutorialTopo(), controller=None)
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
