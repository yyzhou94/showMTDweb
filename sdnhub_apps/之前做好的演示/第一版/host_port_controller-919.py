#coding=utf-8
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER,DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib import hub
from ryu.lib.packet import ether_types

# from ryu.lib.packet import ether_types
# import ryu.utils as utils
import time
import sys
import os
import random

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

attacker_ip = '10.0.0.1'
attacker_mac = '10:00:00:00:00:01'

host_port_controller_enable = False
# 实际存活主机
mininet = True
if mininet:
    ipv4_dsts_net_addr = '10.0.0.'
    ipv4_dsts = {}
    for i in range(1,22):
        p=str(i)
        ip=ipv4_dsts_net_addr+p
        ipv4_dsts[ip]=0
else:
    ipv4_dsts = {'192.168.2.221':0, '192.168.2.221':0, '192.168.2.222':0, '192.168.2.223':0}
broad_dst = 'ff:ff:ff:ff:ff:ff'

SLEEP_PERIOD = 90

#回复SYN-ACK的概率
Psa=20
#回复ACK的概率
Pa=40
#回复RST的概率
Pr=90
#显示在线主机的比例
HIDE=50
# HIDE=100
#伪装离线主机的比例
FAKE=50
#攻击者的端口
attacker_port=1

class HostPort(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(HostPort, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.stat_port = {}
        #虚拟主机列表
        self.virtual_host = {}
        #路径表
        self.datapaths = {}

        self.circle_thread = hub.spawn(self._circle)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths and datapath.id not in [6,7,8]:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        print 'Switch_Features_Handler'
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        # self.add_flow(datapath, 0, match, actions)

    #定时清空流表，mac_to_port表，更新虚拟主机列表中虚拟主机状态
    def _circle(self):
        while True:
            #对于路径中所有的交换机删除与攻击者有关的流表项
            # if host_port_controller_enable == True:    
            for datapath in self.datapaths.values():
                ofp = datapath.ofproto
                ofp_parser = datapath.ofproto_parser

                cookie = cookie_mask = 0
                table_id = 0
                idle_timeout = hard_timeout = 0
                priority = 32768
                buffer_id = ofp.OFPCML_NO_BUFFER
                #目的为攻击者的流表
                match = ofp_parser.OFPMatch()
                #match = ofp_parser.OFPMatch(eth_dst=attacker_mac)
                actions = [ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL,0)]
                inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                req = ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                            table_id, ofp.OFPFC_DELETE,
                                            idle_timeout, hard_timeout,
                                            priority, buffer_id,
                                            ofp.OFPP_ANY, ofp.OFPG_ANY,
                                            ofp.OFPFF_SEND_FLOW_REM,
                                            match, inst)

                datapath.send_msg(req)
                match = ofp_parser.OFPMatch()
                actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
                self.add_flow(datapath, 0, match, actions)
                print "has been in _circle and addflow"

                if datapath.id==1:
                    match = ofp_parser.OFPMatch(in_port=5)
                    actions = []
                    # self.add_flow(datapath, 100, match, actions)
            #对虚拟主机列表中已经存在的主机，在新的周期开始时，根据FAKE决定伪装的比例
            self.mac_to_port.clear()
            for host in self.virtual_host:
                for mac in self.virtual_host[host]:
                    if random.randrange(1,101) < FAKE:
                        self.virtual_host[host][mac] =1
                    else:
                        self.virtual_host[host][mac] =0
            for ip in ipv4_dsts:
                if random.randrange(1,101) < HIDE:
                    ipv4_dsts[ip] = 1
                else:
                    ipv4_dsts[ip] = 0
            hub.sleep(SLEEP_PERIOD)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        
        print "packet  in"
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        #avoid broadcast from ipv6 or LLDP
        if eth.ethertype==ether_types.ETH_TYPE_LLDP or eth.ethertype==ether_types.ETH_TYPE_IPV6:
            # ignore lldp packet
            return

        
        # if host_port_controller_enable == True:

        if dpid == 1 :

            header_list = dict(
                (p.protocol_name, p)for p in pkt.protocols if type(p) != str)

            # Output Message
            # self.logger.info(
            #     'OFPPacketIn received:\nin_port=%d buffer_id=%x '
            #     'total_len=%d table_id=%d cookie=%d',
            #     in_port, msg.buffer_id, msg.total_len, msg.table_id, msg.cookie)
            # print 'header=', header_list
            # print 'data=',utils.hex_array(msg.data)

            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port.setdefault(dpid, {})
            self.mac_to_port[dpid][src] = in_port
            # if host_port_controller_enable == True:

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            #收到TCP包
            if TCP in header_list and header_list[IPV4].src == attacker_ip:
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
                                            ethertype=ether.ETH_TYPE_IP))
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
                                            ethertype=ether.ETH_TYPE_IP))
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
                                            ethertype=ether.ETH_TYPE_IP))
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

            if out_port != ofproto.OFPP_FLOOD:
                if ARP in header_list:
                    #攻击方在广播后第一次发送的ARP请求包都添加流表
                    if header_list[ARP].dst_ip == attacker_ip:
                        #在攻击方第一次广播时，目标主机会ARP回复，根据HIDE概率决定是否给攻击方回复
                        if ipv4_dsts[header_list[ARP].src_ip] == 1:
                            match = parser.OFPMatch(
                                eth_src=src, eth_type=ether.ETH_TYPE_ARP, eth_dst=dst)
                            self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                            return
                        else:
                            actions = []
                            match = parser.OFPMatch(
                                eth_src=src, eth_type=ether.ETH_TYPE_ARP, eth_dst=dst)
                            self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                            return
                    else:
                        match = parser.OFPMatch(
                            eth_src=src, eth_type=ether.ETH_TYPE_ARP, eth_dst=dst)
                        self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                        return
                elif ICMP in header_list:
                    #在线主机收到攻击方的ICMP请求说明攻击方收到了ARP回复，直接添加即可
                    #攻击方只会向在他看来在线的主机，即有ARP回复的主机发送ICMP请求，所对于CMP请求，若目标主机真实在线，添加流表即可，若不在线伪装ICMP回复包即可
                    if header_list[IPV4].dst == attacker_ip:
                        if ipv4_dsts[header_list[IPV4].src] == 0:
                            actions = []
                            match = parser.OFPMatch(
                                eth_src=src, eth_type=ether.ETH_TYPE_IP, ip_proto=1,
                                eth_dst=dst)
                            self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                            return
                        else:
                            match = parser.OFPMatch(
                                eth_src=src, eth_type=ether.ETH_TYPE_IP, ip_proto=1,
                                eth_dst=dst)
                            self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                            return
                    else:
                        match = parser.OFPMatch(
                            eth_src=src, eth_type=ether.ETH_TYPE_IP, ip_proto=1,
                            eth_dst=dst)
                        self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                        return
                # 正常TCP连接
                elif TCP in header_list:
                    match = parser.OFPMatch(
                        eth_src=src, eth_type=ether.ETH_TYPE_IP, ip_proto=6,
                        eth_dst=dst)
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
            else:
                #如果是不在线主机
                if ARP in header_list and header_list[ARP].dst_ip not in ipv4_dsts:
                    #在虚拟主机列表中不存在，即第一次访问这个不在线主机
                    if header_list[ARP].dst_ip not in self.virtual_host:
                        #生成随机MAC地址
                        eth_src = attacker_mac
                        Maclist=[]
                        for i in range(1,7):
                            randstr = "".join(random.sample("0123456789abcdef",2))
                            Maclist.append(randstr)
                        randmac = ":".join(Maclist)
                        #因为是新的不在线主机，要根据FAKE概率决定其是否伪装
                        if random.randrange(1,101) < FAKE:
                            #若伪装则组装虚假回复包，并在虚拟主机料表中将其设为1，即在线
                            self.virtual_host.setdefault(header_list[ARP].dst_ip,{})
                            self.virtual_host[header_list[ARP].dst_ip][randmac] = 1
                            pkt = packet.Packet()
                            pkt.add_protocol(ethernet.ethernet(dst=src, src=randmac,
                                                    ethertype=ether.ETH_TYPE_ARP))
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
                        eth_src = attacker_mac
                        for mac in self.virtual_host[header_list[ARP].dst_ip]:
                            randmac = mac
                        #如果在线组装虚假包，不是则不管
                        if self.virtual_host[header_list[ARP].dst_ip][randmac] == 1:
                            pkt = packet.Packet()
                            pkt.add_protocol(ethernet.ethernet(dst=src, src=randmac,
                                                    ethertype=ether.ETH_TYPE_ARP))
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
                    for mac in self.virtual_host[header_list[IPV4].dst]:
                        if self.virtual_host[header_list[IPV4].dst][mac] == 1:
                            ip = header_list[IPV4].dst
                            pkt = packet.Packet()
                            pkt.add_protocol(ethernet.ethernet(dst=src,
                                                        src=dst,
                                                        ethertype=ether.ETH_TYPE_IP))
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
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions)
            datapath.send_msg(out)
        else:
            print "the process has been in else"
            if eth.ethertype == ether_types.ETH_TYPE_LLDP:
                # ignore lldp packet
                return
            dst = eth.dst
            src = eth.src

            dpid = datapath.id
            self.mac_to_port.setdefault(dpid, {})

            # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port

            # if host_port_controller_enable == True:

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
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
