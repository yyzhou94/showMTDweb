# -*- coding: utf-8 -*-
"""
Author: gztsoul
Time: 2016/10/11 17:00
Licence : GZT licence
Instruction: 

统计主机之间相互通信的数据包的数目。

初始阶段：该阶段为网络中没有部署MTD策略，主机之间可以互相通信,实验时需要模拟该阶段的通信信息。
MTD阶段：该阶段统计上个阶段中主机通信的数据包数目，进而决定部署的策略。
         通信数目更多的主机更经常访问，更大的可能禁止那些相互直接访问较少的主机通信。
         但是通信较少的正常主机更可能被禁止。
修改日志：
该版本不再有 “初始阶段” 和 “MTD阶段”，所有的控制都是由 START_MTD和MONITOR_PERIOD参数调控，
START_MTD: 为True表示开启MTD， 为False表示关闭MTD。
"""
# gzt mark: 
#    1、控制器与交换机之间的通信时间非常短，低于0.01s，10ms左右，
#    2、ping的往返时间： 国内主机： 低于1ms
#    3、 当经过20-30个ICMP数据包之后（估计为timeout控制），才会提示 “目的主机不可达”

#数据不稳定的原因：
#当在主机被封禁之后，发往该主机的目的主机会被当成
#从来没有通信的主机之间互相通信，再一次阻断两台主机之间的相互通信
# 如此不断加深，
# 再加上没有所谓的数据收集阶段，所以结果的不稳定也就不言而喻了
# 为了更容易看到结果，现在调整
# 虚假主机在线：50%
# 正常主机效果：
# 已经有通信量的主机：1-（50%+(i+1)/len）的几率且len>=6才可能被封禁
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

import random
import datetime

from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import vlan
ETHERNET = ethernet.ethernet.__name__
VLAN = vlan.vlan.__name__
IPV4 = ipv4.ipv4.__name__
ARP = arp.arp.__name__
ICMP = icmp.icmp.__name__
TCP = tcp.tcp.__name__
UDP = udp.udp.__name__

mininet = True
if mininet:
    ipv4_dsts_net_addr = '10.0.0.'
    ipv4_dsts = {}
    for i in range(1,23):
        p=str(i)
        ip=ipv4_dsts_net_addr+p
        ipv4_dsts[ip]=0

    # gzt mark: switch_link_hosts 可以看成总的链路信息
    # switch_link_hosts = {dpid : {port:(MAC_ADDR, ip)} }
    IP_ADDR = ['10.0.0.'+'%d' %(i+1) for i in range(22)]
    MAC_ADDR = ['10:00:00:00:00:'+'%02d' %(i+1) for i in range(22)]
    switch_link_hosts = {1:{1:(MAC_ADDR[0],IP_ADDR[0])}, 7:{1:(MAC_ADDR[21],IP_ADDR[21])}}
    for i in range(4):
        switch_link_hosts.setdefault(i+2, {})
        for j in range(5):
            switch_link_hosts[i+2][j+1] = (MAC_ADDR[5*i + j + 1],IP_ADDR[5*i + j + 1])
else:
    ipv4_dsts = {'192.168.2.221':0, '192.168.2.221':0, '192.168.2.222':0, '192.168.2.223':0}

MONITOR_PERIOD = 20
START_MTD = False
FAKE = 50
DROP_PERCENT = 0.5
SHORT_SEQ_LEN = 6
host_scan_enable = False

# priority
# 漏表项为0， 正常匹配项为 2，drop表项为3，IPv6表项的优先级为6
IPV6_PRIORITY = 6

class SimpleMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor, self).__init__(*args, **kwargs)
        self.name = 'monitor'
        self.datapaths = {}
        self.mac_to_port = {}
        self.host_as_src = {} # { src_MAC : {dst_mac:packet_count} }
        self.pre_host_as_src = {} # {src : {dst:packet_count} }
        self.hosts_to_switch = {}       # switch linked hosts { dpid : {port:host_mac} }
        self.drop_comm = {}       # {(eth1,eth2):percent}
        self.virtual_host = {}   # 虚拟主机列表
        self.monitor_thread = hub.spawn(self._monitor)



    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # in this, ev has the attribute 'msg'
        # print 'in function switch feature'
        # print datetime.datetime.now()
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # ignore loop
        if datapath.id == 8:
            return
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        # print 'in datapath %016x' %datapath.id

        #gzt mark: This is to add flow entry to ignore IPv6
        # match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6)
        # actions = []
        # self.add_flow(datapath, IPV6_PRIORITY, match, actions)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        # in this, ev has no attribute msg
        # print 'in function state change'
        # print datetime.datetime.now()
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]
        # print self.datapaths

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # print 'In packet in handler'
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        #print '############################'
        # print eth.ethertype
        #print '###########################'
        # ipv6_packet = pkt.get_protocols(ipv6.ipv6)[0]
        # print ipv6_packet

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        # if eth.ethertype == ether_types.ETH_TYPE_IPV6:
        #     # ignore ipv6 packet
        #     return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        header_list = dict(
                (p.protocol_name, p)for p in pkt.protocols if type(p) != str)
        # 处理从来没有通信的主机
        # gzt mark: 该处的处理逻辑需要完善
        # TO-DO: 逻辑需要修改
        if host_scan_enable == True:
            # print "i am in here"
            if START_MTD:
                if eth.ethertype == ether_types.ETH_TYPE_ARP:
                    arp_pkt = pkt.get_protocols(arp.arp)[0]
                    opcode = arp_pkt.opcode
                    src_ip = arp_pkt.src_ip
                    if opcode == 1:
                        # print arp_pkt
                        # TO-DO 此处有keyerr， 
                        # 需要判断 switch_link_hosts是否有dpid 键值
                        if dpid in switch_link_hosts and (src, src_ip) in switch_link_hosts[dpid].values():
                            dst_ip = arp_pkt.dst_ip
                            if dst_ip in ipv4_dsts:
                                # TO-DO 此处判断dst_ip 是否在该网络中
                                eth_dst = None
                                dpid2 = 0
                                for dp_id in switch_link_hosts:
                                    for port in switch_link_hosts[dp_id]:
                                        if dst_ip == switch_link_hosts[dp_id][port][1]:
                                            eth_dst = switch_link_hosts[dp_id][port][0]
                                            dpid2 = dp_id
                                            break
                                    if dpid2:
                                        break
                                percent = self.drop_comm[(src,eth_dst)] if (src,eth_dst) in self.drop_comm else (1-DROP_PERCENT)
                                # print percent
                                if random.randrange(1,101) >= percent*100 and eth_dst:
                                    # print 'in add drop flow'
                                    actions = []
                                    self.add_flow(datapath, 3, parser.OFPMatch(eth_src=src,eth_dst=eth_dst), actions)
                                    self.add_flow(datapath, 3, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP,
                                                                            eth_src=src, arp_tpa=dst_ip), actions)
                                    datapath = self.datapaths[dpid2]
                                    self.add_flow(datapath, 3, parser.OFPMatch(eth_src=eth_dst,eth_dst=src),actions)
                                    self.add_flow(datapath, 3, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP,
                                                                            eth_src=eth_dst, arp_tpa=src_ip), actions)
                                    self.drop_comm.setdefault( (src, eth_dst), 0.2)
                                    return

            self.mac_to_port.setdefault(dpid, {})

            # self.logger.info("packet in %s %s %s %s %s", dpid, src, dst, in_port, eth.ethertype)

            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port


            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 2, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 2, match, actions)

            # gzt mark: lpy们的处理
            elif START_MTD:
                #如果是不在线主机
                if ARP in header_list and header_list[ARP].dst_ip not in ipv4_dsts:
                    # print 'I am here START_MTD,fake arp packet'
                    #在虚拟主机列表中不存在，即第一次访问这个不在线主机
                    if header_list[ARP].dst_ip not in self.virtual_host:
                        #生成随机MAC地址
                        eth_src = src
                        Maclist=['00','00']
                        for i in range(4):
                            randstr = "".join(random.sample("0123456789abcdef",2))
                            Maclist.append(randstr)
                        randmac = ":".join(Maclist)
                        # print randmac
                        #因为是新的不在线主机，要根据FAKE概率决定其是否伪装
                        if random.randrange(1,101) < FAKE:
                            #若伪装则组装虚假回复包，并在虚拟主机料表中将其设为1，即在线
                            # print 'virtual host on'
                            self.virtual_host.setdefault(header_list[ARP].dst_ip,{})
                            self.virtual_host[header_list[ARP].dst_ip][randmac] = 1
                            pkt = packet.Packet()
                            pkt.add_protocol(ethernet.ethernet(dst=src, src=randmac,
                                                        ethertype=ether_types.ETH_TYPE_ARP))
                            pkt.add_protocol(arp.arp(opcode=2,
                                                    src_mac=randmac,
                                                    src_ip=header_list[ARP].dst_ip,
                                                    dst_mac=src,
                                                    dst_ip=header_list[ARP].src_ip))
                            pkt.serialize()
                            data = pkt.data
                            actions = [parser.OFPActionOutput(in_port)]
                            out = parser.OFPPacketOut(
                                    datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                    in_port=datapath.ofproto.OFPP_CONTROLLER,
                                    actions=actions, data=data)
                            datapath.send_msg(out)
                            return
                        else:
                            #若不伪装则组在虚拟主机料表中将其设为0，即不在线
                            self.virtual_host.setdefault(header_list[ARP].dst_ip,{})
                            self.virtual_host[header_list[ARP].dst_ip][randmac] = 0
                            return
                    #如果存在于虚拟主机列表中，即不是第一次，则根据是否在线，即是1还是0决##定是否组装虚假包
                    else:
                        eth_src = src
                        # gzt mark: 此处的randmac为for 语句内的局部变量，下面if的语句绝对有错误
                        randmac = self.virtual_host[header_list[ARP].dst_ip].keys()[0]
                        # for mac in self.virtual_host[header_list[ARP].dst_ip]:
                        #    randmac = mac
                        #如果在线组装虚假包，不是则不管
                        if self.virtual_host[header_list[ARP].dst_ip][randmac] == 1:
                            pkt = packet.Packet()
                            pkt.add_protocol(ethernet.ethernet(dst=src, src=randmac,
                                                    ethertype=ether_types.ETH_TYPE_ARP))
                            pkt.add_protocol(arp.arp(opcode=2,
                                                    src_mac=randmac,
                                                    src_ip=header_list[ARP].dst_ip,
                                                    dst_mac=src,
                                                    dst_ip=header_list[ARP].src_ip))
                            pkt.serialize()
                            data = pkt.data
                            actions = [parser.OFPActionOutput(in_port)]
                            out = parser.OFPPacketOut(
                                    datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                    in_port=datapath.ofproto.OFPP_CONTROLLER,
                                    actions=actions, data=data)
                            datapath.send_msg(out)
                            return
                #针对不在线主机的ICMP请求，只要组装虚假包即可
                elif ICMP in header_list and header_list[IPV4].dst not in ipv4_dsts:
                    # print 'I am here START_MTD,fake ICMP packet'
                    for mac in self.virtual_host[header_list[IPV4].dst]:
                        if self.virtual_host[header_list[IPV4].dst][mac] == 1:
                            # print 'FAKE ICMP packet'
                            ip = header_list[IPV4].dst
                            pkt = packet.Packet()
                            pkt.add_protocol(ethernet.ethernet(dst=src,
                                                        src=dst,
                                                        ethertype=ether_types.ETH_TYPE_IP))
                            pkt.add_protocol(ipv4.ipv4(dst=header_list[IPV4].src,
                                                       src=header_list[IPV4].dst,
                                                       proto=1))
                            pkt.add_protocol(icmp.icmp(type_=0, code=0, csum=0,
                                                       data=header_list[ICMP].data))
                            try:
                                pkt.serialize()
                            except Exception,e:
                                print e
                                print self.virtual_host
                                print ipv4_dsts
                                time.sleep(10)
                            data = pkt.data
                            actions = [parser.OFPActionOutput(in_port)]
                            out = parser.OFPPacketOut(
                                        datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                        in_port=datapath.ofproto.OFPP_CONTROLLER,
                                        actions=actions, data=data)
                            datapath.send_msg(out)
                            return
                        else:
                            return
                elif TCP in header_list and header_list[IPV4].dst not in ipv4_dsts:
                    # print 'I am here START_MTD,fake ICMP packet'
                    ipv4_src = header_list[IPV4].dst
                    ipv4_dst = header_list[IPV4].src
                    src_port = header_list[TCP].dst_port
                    dst_port = header_list[TCP].src_port
                    ack = header_list[TCP].seq+1
                    option=header_list[TCP].option
                    #根据Psa回复SYN ACK
                    if random.randrange(1,101) < Psa:
                        pkt = packet.Packet()
                        pkt.add_protocol(ethernet.ethernet(dst=src, src=dst,
                                                ethertype=ether_types.ETH_TYPE_IP))
                        pkt.add_protocol(ipv4.ipv4(flags=0x02, proto=6,
                                                src=ipv4_src,dst=ipv4_dst))
                        pkt.add_protocol(tcp.tcp(src_port=src_port, dst_port=dst_port,
                                                 seq=random.randrange(1, 0xFFFFFFFF),
                                                 ack=ack, bits=0x12, window_size=1024,
                                                 option=option))
                        pkt.serialize()
                        data = pkt.data
                        actions = [parser.OFPActionOutput(in_port)]
                        out = parser.OFPPacketOut(
                                    datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                    in_port=datapath.ofproto.OFPP_CONTROLLER,
                                    actions=actions, data=data)
                        datapath.send_msg(out)
                        return
                    #根据Psa回复ACK
                    elif random.randrange(1,101) < Pa and random.randrange(1,101) >Psa:
                        pkt = packet.Packet()
                        pkt.add_protocol(ethernet.ethernet(dst=src, src=dst,
                                                ethertype=ether_types.ETH_TYPE_IP))
                        pkt.add_protocol(ipv4.ipv4(flags=0x02, proto=6,
                                                src=ipv4_src,dst=ipv4_dst))
                        pkt.add_protocol(tcp.tcp(src_port=src_port, dst_port=dst_port,
                                                 seq=random.randrange(1, 0xFFFFFFFF),
                                                 ack=ack, bits=0x10, window_size=1024,
                                                 option=option))
                        pkt.serialize()
                        data = pkt.data
                        actions = [parser.OFPActionOutput(in_port)]
                        out = parser.OFPPacketOut(
                                    datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                    in_port=datapath.ofproto.OFPP_CONTROLLER,
                                    actions=actions, data=data)
                        datapath.send_msg(out)
                        return
                    #根据Psa回复RST
                    elif random.randrange(1,101) < Pr and random.randrange(1,101) >Pa:
                        pkt = packet.Packet()
                        pkt.add_protocol(ethernet.ethernet(dst=src, src=dst,
                                                ethertype=ether_types.ETH_TYPE_IP))
                        pkt.add_protocol(ipv4.ipv4(flags=0x02, proto=6,
                                                src=ipv4_src,dst=ipv4_dst))
                        pkt.add_protocol(tcp.tcp(src_port=src_port, dst_port=dst_port,
                                                 seq=random.randrange(1, 0xFFFFFFFF),
                                                 ack=ack, bits=0x04, window_size=1024,
                                                 option=option))
                        pkt.serialize()
                        data = pkt.data
                        actions = [parser.OFPActionOutput(in_port)]
                        out = parser.OFPPacketOut(
                                    datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                    in_port=datapath.ofproto.OFPP_CONTROLLER,
                                    actions=actions, data=data)
                        datapath.send_msg(out)
                        return
                    else:
                        return
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            # print 'The last two line,Just packet out'
            datapath.send_msg(out)


    def _monitor(self):
        while True:
            # print 'In monitor thread'
            # if host_scan_enable == True:

            self.pre_host_as_src = self.host_as_src
            self.host_as_src.clear()
            for dp in self.datapaths.values():
                self._request_stats(dp)
                # print dp

            # print datetime.datetime.now()

            hub.sleep(MONITOR_PERIOD*0.1)
            # if self.mac_to_port:
            #     print self.mac_to_port
            # if self.host_as_src:
            #     print self.host_as_src
            if host_scan_enable == True:
                if START_MTD:
                    for host in self.virtual_host:
                        for mac in self.virtual_host[host]:
                            if random.randrange(1,101) < FAKE:
                                self.virtual_host[host][mac] = 1
                            else:
                                self.virtual_host[host][mac] = 0
                    self.flow_entries_update()
                else:
                    self._clear_drop_entry()
        hub.sleep(MONITOR_PERIOD*0.99)

    def flow_entries_update(self):
        # calculate packet: host as dst or host receives numbers of packets
        # 统计各个主机之间通信的数据包 src
        # 一台主机发送给另一台主机的数据包
        # 根据两个阶段的数据进行决策

        # 对于已经封禁的，决定是否解封
        drop_host_comm = []
        for (eth1, eth2) in self.drop_comm:
            self.drop_comm[(eth1,eth2)] *= 2
            if random.randrange(1,101) > self.drop_comm[(eth1, eth2)]*100:
                continue
            else:
                (dpid1, in_port1, host_ip1) = self._get_info(eth1)
                (dpid2, in_port2, host_ip2) = self._get_info(eth2)
                datapath = self.datapaths[dpid1]
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                self.del_flow(datapath, parser.OFPMatch(eth_src=eth1,eth_dst=eth2))
                self.del_flow(datapath, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP,
                                                        eth_src=eth1, arp_tpa=host_ip2))

                datapath = self.datapaths[dpid2]
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                self.del_flow(datapath, parser.OFPMatch(eth_src=eth2,eth_dst=eth1))
                self.del_flow(datapath, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP,
                                                        eth_src=eth2, arp_tpa=host_ip1))
                # 记录要解封的数据
                drop_host_comm.append( (eth1, eth2) )
        # 删除已经解封的数据
        for i in drop_host_comm:
            del self.drop_comm[i]


        self.host_as_src
        host_communication_pkts = []  # [(eth1, eth2, packet)]
        # 数据包数目的计算, 仅对当前回合未封禁的
        for eth_src in self.host_as_src:
            eth1 = eth_src
            for eth_dst in self.host_as_src[eth_src]:
                eth2 = eth_dst
                packet_count = self.host_as_src[eth_src][eth_dst]
                if eth2 in self.host_as_src and eth1 in self.host_as_src[eth2]:
                    packet_count += self.host_as_src[eth2][eth1]
                if (eth1, eth2, packet_count) not in host_communication_pkts and (eth2, eth1, packet_count) not in host_communication_pkts:
                    host_communication_pkts.append( (eth1, eth2, packet_count) )

        sequen_host_comm_pkts = sorted(host_communication_pkts, key=lambda ele:ele[2])
        seq_len = len(sequen_host_comm_pkts)

        # MTD的比例可以调节，现在不妨设为 0.5（实际应该比较低）
        # TO-DO: 需要实现 self.get_info(eth)
        # 排在低位的通信量有 0.5+(i+1)/seq_len的几率阻断通信
        # 对于未封禁的，决定如何处理
        for i in xrange(int(seq_len*0.5)):
            if random.randrange(1,101) > ( (i+1)*1.0/seq_len + 1-DROP_PERCENT)*100 and seq_len >= SHORT_SEQ_LEN:
                (eth1, eth2, pkts) = sequen_host_comm_pkts[i]
                self.drop_comm.setdefault( (eth1, eth2), (i+1)*1.0/seq_len + 1-DROP_PERCENT )
                # print '!!!!!!!!!!!!!!!!!!!!!!!!',eth1,eth2
                (dpid1, in_port1, host_ip1) = self._get_info(eth1)
                # print '#########################',dpid1, in_port1, host_ip1
                (dpid2, in_port2, host_ip2) = self._get_info(eth2)
                # print '*************************',dpid2, in_port2, host_ip2
                datapath = self.datapaths[dpid1]
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                # 不需要删除原流表，添加阻断流表:1、阻断数据包，2、阻断arp包
                # self.del_flow(datapath, parser.OFPMatch(in_port=in_port, eth_dst=eth2))
                actions = []
                self.add_flow(datapath, 3, parser.OFPMatch(eth_src=eth1,eth_dst=eth2), actions)
                # print 'before eth1 add flow',eth1, host_ip2
                self.add_flow(datapath, 3, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP,
                                                            eth_src=eth1, arp_tpa=host_ip2), actions)
                # print 'after eth1 add flow',eth1, host_ip2
                datapath = self.datapaths[dpid2]
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                actions = []
                # self.del_flow(datapath, parser.OFPMatch(in_port=in_port, eth_dst=eth1))
                self.add_flow(datapath, 3, parser.OFPMatch(eth_src=eth2,eth_dst=eth1), actions)
                self.add_flow(datapath, 3, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP,
                                                            eth_src=eth2, arp_tpa=host_ip1), actions)



    def _clear_drop_entry(self):
        for (eth1, eth2) in self.drop_comm:
            (dpid1, in_port1, host_ip1) = self._get_info(eth1)
            (dpid2, in_port2, host_ip2) = self._get_info(eth2)
            datapath = self.datapaths[dpid1]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            self.del_flow(datapath, parser.OFPMatch(eth_src=eth1,eth_dst=eth2))
            self.del_flow(datapath, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP,
                                                    eth_src=eth1, arp_tpa=host_ip2))

            datapath = self.datapaths[dpid2]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            self.del_flow(datapath, parser.OFPMatch(eth_src=eth2,eth_dst=eth1))
            self.del_flow(datapath, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP,
                                                        eth_src=eth2, arp_tpa=host_ip1))
        self.drop_comm.clear()
        self.virtual_host.clear()

    def _get_info(self, eth):
        dpid = 0
        in_port = 0
        host_ip = None
        for dp_id in switch_link_hosts:
            for port in switch_link_hosts[dp_id]:
                if eth == switch_link_hosts[dp_id][port][0]:
                    dpid = dp_id
                    in_port = port
                    host_ip = switch_link_hosts[dp_id][port][1]
                    # print 'in get info',dpid,host_ip
                    break
            if dpid:
                break
        return (dpid, in_port, host_ip)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # This is flow stats request
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        # This is port stats request
        # req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        # datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        # cautions: different ev have different structure, be careful.
        # gzt mark: 只要能得到以 packet(src --> dst) ,则根据所有主机的数据，
        # 就能获取以某个主机为源地址或者目的地址的数据包
        body = ev.msg.body
        datapath = ev.msg.datapath
        dpid = ev.msg.datapath.id

        # 如果该交换机连接有主机
        if dpid in switch_link_hosts and host_scan_enable==True:
            for stat in sorted( [flow for flow in body if flow.priority == 2 ]):
                # 源地址为此的主机 连接的交换机, 该处可能会有不止一个数据
                if stat.match['in_port'] in switch_link_hosts[dpid]:
                    mac = switch_link_hosts[dpid][stat.match['in_port']][0]
                    self.host_as_src.setdefault(mac, {})
                    self.host_as_src[mac][stat.match['eth_dst']] = stat.packet_count

        # print 'in flow stats reply handler'
        # print datetime.datetime.now()
    
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        body = ev.msg.body
        """
        print '%%%%%%%%%%%%%%%%%%%%%%%%%'
        print ev.msg
        print '&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&'
        print ev.msg.datapath.id
        print

        self.logger.info('datapath                port     '
                         'rx-pkts    rx-bytes  rx-error '
                         'tx-pkts    tx-bytes  tx-error ')
        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                             ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)
        """

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                    instructions=inst, buffer_id=buffer_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                    instructions=inst)
        datapath.send_msg(mod)

    def del_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(datapath=datapath,
                                command=ofproto.OFPFC_DELETE,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY,
                                match=match)
        datapath.send_msg(mod)


