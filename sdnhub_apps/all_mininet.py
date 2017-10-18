#!/usr/bin/python
# -*- coding: utf-8 -*-

from mininet.cli import CLI
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.topo import Topo
from mininet.node import RemoteController
import os
from bottle import route , run ,template
import conf



def addFlows(hide, priority=0):
    for i in range(1, 9):
        if i not in hide:
            os.system("ovs-ofctl add-flow s%d priority=%d,actions=CONTROLLER:65535" % (i, priority))

def topoDiscover():
    topo = MyTopo()

    net = Mininet(topo=topo, link=TCLink, controller=RemoteController)

    @route('/del_flows/')
    def cmddelflow():
        for i in range(1,9):
            os.system("sudo ovs-ofctl del-flows  s%d" %i )
        for i in range(1,8):
            os.system("ovs-ofctl add-flow s%d priority=0,actions=CONTROLLER:65535" %i)


    @route('/group_flows/')
    def show_group_flows():
        for i in range(1,9):
            os.system("ovs-ofctl  dump-groups -O OpenFlow13  s%d" %i)


    @route('/ping/')
    def cmdping():
        for i in range(1,9):
            os.system("sudo ovs-ofctl del-flows  s%d" %i )
        for i in range(1,9):
            os.system("ovs-ofctl add-flow s%d priority=0,actions=CONTROLLER:65535" %i)
        h1,h22 = net.get ('h1','h22')
        print 'i am in flow_detect'
        result = h1.cmd('ping -c50  '  +  h22.IP())
        res = result.replace('\r\n','<br>')
        return res
    @route('/version_nmap/')
    def cmdversion():
        h1,h2 = net.get('h1','h2')
        print 'i am in os_web_detect'
        result = h1.cmd(' nmap   ' + h2.IP() +'   -A -p 80   ')
        res = result.replace('\r\n','<br>')
        return res


    @route('/portscan/')
    def portscan():
        for i in range(1,9):
            os.system("sudo ovs-ofctl del-flows  s%d" %i )
            # os.system("ovs-ofctl add-flow s%d priority=0,actions=CONTROLLER:65535" %i)
            # print "del-flow in s%d" %i
        for i in range(1,8):
            os.system("ovs-ofctl add-flow s%d priority=0,actions=CONTROLLER:65535" %i)
        h1,h2 = net.get('h1','h2')
        print 'i am in portscan'

        result = h1.cmd(' nmap  ' + h2.IP() + '-21 -p T:17,20,21,22,43,80,119,169,143 ')
        res = result.replace('\r\n','<br>')
        return res

    @route('/arpscan/')
    def arpscan():
        for i in range(1,9):
            os.system("sudo ovs-ofctl del-flows  s%d" %i )
            # os.system("ovs-ofctl add-flow s%d priority=0,actions=CONTROLLER:65535" %i)
            # print "del-flow in s%d" %i
        addFlows([6, 8])
        h1,h2 = net.get('h1','h2')
        print 'i am in hostscan'
        result = h1.cmd(' nmap -n -sn ' + h2.IP()+'-40' )
        res = result.replace('\r\n','<br>')
        return res




    @route('/icmpscan/')
    def icmpscan():
        for i in range(1,9):
            os.system("sudo ovs-ofctl del-flows  s%d" %i )
            # os.system("ovs-ofctl add-flow s%d priority=0,actions=CONTROLLER:65535" %i)
            # print "del-flow in s%d" %i
        addFlows([6, 8])
        h1,h2 = net.get('h1','h2')
        print h2.IP()
        result = h1.cmd(' nmap -PE --send-ip ' + h2.IP()+'-21 -p T:80 ' )
        res = result.replace('\r\n','<br>')
        return res

    @route('/net/')
    def shownet():
        os.system("net status")

    @route ('/stop')
    def stop():
        "Exit"
        os.system('sudo ovs-vsctl del-port s1 ens33')
        os.system('sudo ifconfig s1 0')
        os.system('sudo ifconfig ens33 192.168.2.254')
        # Added by junjie
        os.system('sudo ovs-vsctl del-port s1 veth0')

        os.system('sudo killall lld2d')
        net.stop()
    @route('/flows/')#此处只能加单影号
    def displayflows():
        for i in range(1,9):
            os.system("ovs-ofctl  dump-flows  s%d" %i)







    # 启动Mininet
    net.start()

    hosts = topo.hosts()
    try:
        # 配置Hosts的MAC地址
        [ net.get(hosts[i]).setMAC('10:00:00:00:00:'+str(i+1)) for i in range(len(hosts)) ]
        [net.get(hosts[i]).setIP('10.0.0.'+str(i+1), 24) for i in range(len(hosts))]
        # 执行各种命令
        [ net.get(hosts[i]).cmd('lld2d ' + hosts[i] + '-eth0') for i in range(len(hosts)) ]
        net.get(hosts[1]).cmd('python -m SimpleHTTPServer 80 &')
        [ net.get(hosts[i]).cmd('route add -net 192.168.2.0/24 dev ' + hosts[i] + '-eth0') for i in range(len(hosts)) ]
        os.system('sudo ovs-vsctl add-port s1 ens33')
        os.system('sudo ifconfig ens33 0')
        os.system('sudo ifconfig s1 %s' %(conf.interface2))
        # Added by junjie
        os.system('sudo ovs-vsctl add-port s1 veth0')

    except Exception,e:
        print e
        net.stop()
    run(host = '%s'%(conf.host) , port = 8000)
    # 启动web端



class MyTopo(Topo):
    def __init__(self):
        Topo.__init__(self)
        switches_num = 8
        hosts_num = 22

        switches = [ self.addSwitch('s' + str(i+1)) for i in range(switches_num) ]
        hosts    = [ self.addHost('h' + str(i+1)) for i in range(hosts_num) ]

        # 连接主机
        # h1 -> s1
        self.addLink(hosts[0], switches[0])
        # Linear,4,5
        for i in range(4):
            for j in range(5):
                self.addLink(hosts[5*i+1+j], switches[i+1])
        # h22 -> s7
        self.addLink(hosts[21], switches[6])

        # 连接交换机
        # Circle
        self.addLink(switches[0], switches[5], delay='5ms')
        self.addLink(switches[5], switches[6], delay='5ms')
        self.addLink(switches[6], switches[7], delay='20ms')
        self.addLink(switches[7], switches[0], delay='20ms')
        # Linear,4(,5)
        self.addLink(switches[0], switches[1])
        self.addLink(switches[1], switches[2])
        self.addLink(switches[2], switches[3])
        self.addLink(switches[3], switches[4])

if __name__ == '__main__':
    setLogLevel('info')
    topoDiscover()
