# -*- coding: utf-8 -*-
"""
Author: gztsoul
Time: 2016/10/18 9:00

Instroduction:

"""
# 通过统计src_mac(ip_port), dst_mac, dst_port 数据，可以获得主机之间通信
# 的强度，
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

import host_info
import datetime
import random

from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import vlan
from ryu.lib.packet import ipv6

from ryu.lib.packet import in_proto

ETHERNET = ethernet.ethernet.__name__
VLAN = vlan.vlan.__name__
IPV4 = ipv4.ipv4.__name__
ARP = arp.arp.__name__
ICMP = icmp.icmp.__name__
TCP = tcp.tcp.__name__
UDP = udp.udp.__name__
IPV6 = ipv6.ipv6.__name__

START_MTD = False
# mininet = True
# if mininet:
#     ipv4_dsts_net_addr = '10.0.0.'
#     ipv4_dsts = {}
#     for i in range(1,22):
#         p=str(i)
#         ip=ipv4_dsts_net_addr+p
#         ipv4_dsts[ip]=0

#     # gzt mark: switch_link_hosts 可以看成总的链路信息
#     # switch_link_hosts = {dpid : {port:(MAC_ADDR, ip)} }
#     IP_ADDR = ['10.0.0.'+'%d' %(i+1) for i in range(22)]
#     MAC_ADDR = ['10:00:00:00:00:'+'%02d' %(i+1) for i in range(22)]
#     switch_link_hosts = {1:{1:(MAC_ADDR[0],IP_ADDR[0])}, 7:{1:(MAC_ADDR[21],IP_ADDR[21])}}
#     for i in range(4):
#         switch_link_hosts.setdefault(i+2, {})
#         for j in range(5):
#             switch_link_hosts[i+2][j+1] = (MAC_ADDR[5*i + j + 1],IP_ADDR[5*i + j + 1])
# else:
#     ipv4_dsts = {'192.168.2.221':0, '192.168.2.221':0, '192.168.2.222':0, '192.168.2.223':0}



NORMAL = 'normal'
ABNORMAL = 'abnormal'
PRIORITY = {NORMAL:1, ARP:2, IPV4:4, IPV6:6, ICMP:11, TCP:12, UDP:12, ABNORMAL:20}
IPV6_PRIORITY = 6
FAKE = 20
switch_link_hosts = host_info.switch_link_hosts
ipv4_dsts = host_info.ipv4_dsts
MONITOR_PERIOD = 30
port_scan_enable = False

Psa = 20
Pa = 40
Pr = 90
FAKE = 50

class PortScan(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(PortScan, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.trans_layer_info = {}  #匹配的传输层信息 {(eth_src,eth_dst):{dst_port:pkt_counts}}
        self.virtual_host = {}      #虚假主机列表
        self.abnormal_flow = {}     #异常流表 {(dpid,in_port,eth_dst,dst_port):match}}
        # self.loop_print_thread = hub.spawn(self._loop_thread)
        self._monitor_thread = hub.spawn(self._monitor)

    # def _loop_thread(self):
        # while True:
        #     hub.sleep(10)
        #     if self.mac_to_port:
        #         print self.mac_to_port
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
                # self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                # self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]
        # print self.datapaths

    def _monitor(self):
        while True:
            # print 'In monitor thread'
            # print datetime.datetime.now()
            self.trans_layer_info.clear()
            for dp in self.datapaths.values():
                self._request_stats(dp)

            hub.sleep(MONITOR_PERIOD*0.05)

            if START_MTD:
                for host in self.virtual_host:
                    for mac in self.virtual_host[host]:
                        if random.randrange(1,101) < FAKE:
                            self.virtual_host[host][mac] = 1
                        else:
                            self.virtual_host[host][mac] = 0
                self.flow_entries_update()
            else:
                self._clear_drop_update()

            hub.sleep(MONITOR_PERIOD*0.95)

    def flow_entries_update(self):
        # 统计主机之间通信的数据包，根据流量的数目进行决策

        # 对于异常回复，决定如何处理
        # 在每个周期内，有50%的概率删除异常恢复流表
        abnormal_trans_flow = []
        for (dpid, in_port, eth_dst, dst_port) in self.abnormal_flow:
            if random.randrange(1,101) < 50:
                continue
            else:
                datapath = self.datapaths[dpid]
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                self.del_flow(datapath, self.abnormal_flow[(dpid,in_port,eth_dst,dst_port)])
                abnormal_trans_flow.append( (dpid,in_port,eth_dst,dst_port) )

        for element in abnormal_trans_flow:
            del self.abnormal_flow[element]
        # 数据包计算，仅仅对当前回合正常回复的数据包
        # trans_layer_info = {(eth_src, eth_dst): {dst_port:packet_count} }
        self.trans_layer_info
        trans_layer_pkts = []
        for (eth_src, eth_dst) in self.trans_layer_info:
            for dst_port in self.trans_layer_info[(eth_src, eth_dst)]:
                packet_count = self.trans_layer_info[(eth_src, eth_dst)][dst_port]
                trans_layer_pkts.append( ((eth_src, eth_dst), dst_port, packet_count) )

        sequen_trans_layer_pkts = sorted(trans_layer_pkts, key=lambda ele: ele[2])
        seq_len = len(sequen_trans_layer_pkts)

        # gzt mark: 还有提高的空间，在概率方面
        # 当前是前80% 正常回复，后20% 有20%的几率异常回复
        for i in xrange(int(seq_len*0.2)):
            if random.randrange(1,101) < 20:
                ((eth_src, eth_dst), dst_port, packet_count) = sequen_trans_layer_pkts[i]
                dpid = 0
                in_port = 0
                for dp_id in switch_link_hosts:
                    for port in switch_link_hosts[dp_id]:
                        if eth_src == switch_link_hosts[dp_id][port][0]:
                            dpid = dp_id
                            in_port = port
                            break
                    break
                if dpid:
                    datapath = self.datapaths[dpid]
                    ofproto = datapath.ofproto
                    parser = datapath.ofproto_parser
                    match = parser.OFPMatch(eth_src=eth_src, eth_dst=eth_dst, eth_type=ether_types.ETH_TYPE_IP,
                                            ip_proto=in_proto.IPPROTO_TCP, tcp_dst=dst_port)
                    actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
                    self.add_flow(datapath, PRIORITY[ABNORMAL], match, actions)
                    self.abnormal_flow.setdefault( (dpid,in_port,eth_dst,dst_port), match)


    def _clear_drop_update(self):
        for (dpid, in_port, eth_dst, dst_port) in self.abnormal_flow:
            datapath = self.datapaths[dpid]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            self.del_flow(datapath, self.abnormal_flow[(dpid,in_port,eth_dst,dst_port)])

        self.abnormal_flow.clear()
        self.virtual_host.clear()

    def _request_stats(self, datapath):
        # self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # This is flow stats request
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # print 'In packet in handler'
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        # if ev.msg.msg_len < ev.msg.total_len:
            # self.logger.debug("packet truncated: only %s of %s bytes",
            #                     ev.msg.msg_len, ev.msg.total_len)

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet and ipv6 packet
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        # if (dst[:6] not in ['00:00:', 'ff:ff:']) or src[:6] not in ['00:00:']:
        # if (dst[:6] != '00:00:' and dst[:6] != 'ff:ff:') or src[:6] != '00:00:':
        #     return

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        header_list = dict(
                (p.protocol_name, p)for p in pkt.protocols if type(p) != str)
        # print '!!!!!!!!!!!!!!!!!!!!!'
        # print header_list
        # print '!!!!!!!!!!!!!!!!!!!!!'
        if port_scan_enable == True:
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]
            # 判断是否需要异常回复
            if TCP in header_list:
                dst_port = header_list[TCP].dst_port
                if (dpid, in_port, dst, dst_port) in self.abnormal_flow:
                    self._abnormal_handler(ev, header_list)
                    return

            match = []
            priority = 0
            # install a flow to avoid packet_in next time
            # switch_link_hosts = {dpid : {port:(MAC_ADDR:IP)} }
            # 判断当前交换机是否是连接发送数据包主机的交换机
            if out_port != ofproto.OFPP_FLOOD:
                if ((dpid in switch_link_hosts and in_port in switch_link_hosts[dpid] and switch_link_hosts[dpid][in_port][0]==src) or
                        (dpid in switch_link_hosts and out_port in switch_link_hosts[dpid] and switch_link_hosts[dpid][out_port][0]==dst)):
                    if ARP in header_list:
                        match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=ether_types.ETH_TYPE_ARP)
                        priority = PRIORITY[ARP]
                    elif TCP in header_list:
                        match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=ether_types.ETH_TYPE_IP,
                                                ip_proto=in_proto.IPPROTO_TCP, tcp_dst=header_list[TCP].dst_port)
                        priority = PRIORITY[TCP]

                        # gzt mark: 开启mtd，对于第一条发往服务器的tcp数据包，需要进行判断，
                        # 是否对其进行mtd处理
                        if START_MTD:
                            if header_list[TCP].dst_port <= 1024:
                                if random.randrange(1,101) < 50:
                                    dst_port = header_list[TCP].dst_port
                                    match = parser.OFPMatch(eth_src=src, eth_dst=dst, eth_type=ether_types.ETH_TYPE_IP,
                                                            ip_proto=in_proto.IPPROTO_TCP, tcp_dst=dst_port)
                                    actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
                                    priority = PRIORITY[ABNORMAL]
                                    self.abnormal_flow.setdefault( (dpid,in_port,dst,dst_port), match)

                    elif UDP in header_list:
                        match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=ether_types.ETH_TYPE_IP,
                                                ip_proto=in_proto.IPPROTO_UDP, udp_dst=header_list[udp].dst_port)
                        priority = PRIORITY[UDP]
                    elif ICMP in header_list:
                        match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=ether_types.ETH_TYPE_IP,
                                                ip_proto=1)
                        priority = PRIORITY[ICMP]
                    else:
                        return
                else:
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                    priority = PRIORITY[NORMAL]
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, priority, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, priority, match, actions)
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                                in_port=in_port, actions=actions, data=msg.data)
                    datapath.send_msg(out)
                    return
            
            # 针对不在线主机，有50%的可能性虚假在线，而对于虚假在线的主机，有
            # 50%的可能性进行回复
            elif START_MTD:
                # 如果是不在线主机
                if ARP in header_list and header_list[ARP].dst_ip not in ipv4_dsts:
                    # print 'I am here START_MTD, fake arp packet'
                    # 在虚拟主机列表中不存在，即第一次访问这个不在线主机
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
                        # gzt mark: 
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
                    mac = header_list[ETHERNET].dst
                    if self.virtual_host[header_list[IPV4].dst][mac] == 1:
                        self._abnormal_handler(ev, header_list)
                        # if random.randrange(1,101) < 50:
                        #     self._abnormal_handler(ev, header_list)
                        #     return
                    return

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

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

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        # cautions: different ev have different structure, be careful.
        # gzt mark: 只要能得到以 ,则根据所有主机的数据，
        # 就能获取以某个主机为源地址或者目的地址的数据包
        body = ev.msg.body
        datapath = ev.msg.datapath
        dpid = ev.msg.datapath.id

        # 如果该交换机连接有主机
        if dpid in switch_link_hosts:
            # print dpid
            for stat in sorted( [flow for flow in body 
                                if (flow.priority == PRIORITY[TCP] and flow.match['tcp_dst'] <= 1024) ]):
                if stat.match['in_port'] in switch_link_hosts[dpid]:
                    eth_src = switch_link_hosts[dpid][stat.match['in_port']][0]
                    eth_dst = stat.match['eth_dst']
                    self.trans_layer_info.setdefault( (eth_src, eth_dst), {})
                    self.trans_layer_info[(eth_src, eth_dst)][stat.match['tcp_dst']] = stat.packet_count

        # print 'in flow stats reply handler'
        # print datetime.datetime.now()

    # 对TCP数据包进行异常处理
    def _abnormal_handler(self, ev, header_list):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        eth_src = header_list[ETHERNET].dst
        eth_dst = header_list[ETHERNET].src
        ipv4_src = header_list[IPV4].dst
        ipv4_dst = header_list[IPV4].src
        src_port = header_list[TCP].dst_port
        dst_port = header_list[TCP].src_port
        ack = header_list[TCP].seq+1
        option=header_list[TCP].option
        #根据Psa回复SYN ACK
        if random.randrange(1,101) < Psa:
            pkt = packet.Packet()
            pkt.add_protocol(ethernet.ethernet(src=eth_src, dst=eth_dst,
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
            pkt.add_protocol(ethernet.ethernet(src=eth_src, dst=eth_dst,
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
            pkt.add_protocol(ethernet.ethernet(src=eth_src, dst=eth_dst,
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
