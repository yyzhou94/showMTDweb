#!usr/bin/python
# -*- coding: utf-8 -*-

# 实验步骤：
# mininet中执行 `h1 ping h22` 观察ICMP包的时延
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, ipv6, icmp
from ryu.lib import hub

# from mininet.mininet.net import Mininet
# from mininet.mininet.node import Node
# from mininet.mininet.link import Link
# # from mininet.mininet.log import setLogLevel,info
# from mininet.mininet.util import quietRun



ETHERNET = ethernet.ethernet.__name__
ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"
ARP = arp.arp.__name__
ICMP = icmp.icmp.__name__
IPV4 = ipv4.ipv4.__name__
IPV6 = ipv6.ipv6.__name__

SLEEP_PERIOD = 4

IP_ADDR = ['10.0.0.1', '10.0.0.22']
ETH_ADDR = ['10:00:00:00:00:01', '10:00:00:00:00:22']

multipath_controller_enable = False


class Multipath(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Multipath, self).__init__(*args, **kwargs)

        self.datapaths = {}
        self.mac_to_port = {}
        self.arp_table = {}
        self.sw = {}

        self.addflowmod_thread = hub.spawn(self._addflowmod)
        # self.print_thread = hub.spawn(self._print)
        self.addflows_thread = hub.spawn(self._addflows)

    def _print(self):
        while True:
            print multipath_controller_enable
            hub.sleep(SLEEP_PERIOD)



    def _addflowmod(self):

        path_id = 0
        paths = [[1, 6, 7], [1, 8, 7]]
        # global multipath_controller_enable
        while True:
            # print 'circle start'
            if multipath_controller_enable == True:
                # print '_addflowmod True'
                for datapath_id in paths[path_id]:
                    if datapath_id not in self.datapaths:
                        continue
                    datapath = self.datapaths[datapath_id]
                    ofp_parser = datapath.ofproto_parser

                    if  datapath_id == 1  :
                        match = ofp_parser.OFPMatch(in_port = 1,eth_dst = ETH_ADDR[1])
                        actions = [ofp_parser.OFPActionOutput(path_id + 2)]
                        print 'datapath_id == 1,in _addflowmod'
                        self.add_flow(datapath, 1, match, actions)
                    elif  datapath_id ==7 :
                        match = ofp_parser.OFPMatch(in_port = 1,eth_dst = ETH_ADDR[0])
                        actions = [ofp_parser.OFPActionOutput(path_id + 2)]
                        print 'datapath_id == 7,in _addflowmod'
                        self.add_flow(datapath, 1, match, actions)

                path_id = (path_id + 1) % 2
            hub.sleep(SLEEP_PERIOD)

    def _addflows(self):
        paths = [1,2,3,4,5,6,7,8]
        while True:
            if multipath_controller_enable == True:
                for datapath_id in paths :
                    datapath = self.datapaths[datapath_id]
                    ofproto = datapath.ofproto
                    ofp_parser = datapath.ofproto_parser
                    if datapath.id == 1 or datapath.id == 7:
                            eth_dst = ETH_ADDR[0] if datapath.id == 1 else ETH_ADDR[1]
                            match = ofp_parser.OFPMatch(eth_dst=eth_dst)
                            # port = 4 if datapath.id == 1 else 3
                            port = 1
                            actions = [ofp_parser.OFPActionOutput(port)]
                            print 'datapath.id == 1,in _state_change_handler'
                            self.add_flow(datapath, 1, match, actions)

                            # in case of there's no flows in first 20s
                            match = ofp_parser.OFPMatch(in_port=1)
                            actions = [ofp_parser.OFPActionOutput(2)]
                            self.add_flow(datapath, 1, match, actions, SLEEP_PERIOD)

                            # send eth_dst==ETHERNET_MULTICAST packages to controller
                            match = ofp_parser.OFPMatch(eth_dst=ETHERNET_MULTICAST)
                            actions = [ofp_parser.OFPActionOutput(
                                ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
                            self.add_flow(datapath, 1, match, actions)
                    elif datapath.id == 6 or datapath.id == 8:
                        match = ofp_parser.OFPMatch(in_port=1)
                        actions = [ofp_parser.OFPActionOutput(2)]
                        self.add_flow(datapath, 1, match, actions)

                        match = ofp_parser.OFPMatch(in_port=2)
                        actions = [ofp_parser.OFPActionOutput(1)]
                        self.add_flow(datapath, 1, match, actions)
            hub.sleep(SLEEP_PERIOD)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        # global multipath_controller_enable
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                # self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
                print 'datapaths have been saved'
                
                ofproto = datapath.ofproto
                ofp_parser = datapath.ofproto_parser
                # if multipath_controller_enable == True:
            
                #     if datapath.id == 1 or datapath.id == 7:
                #         eth_dst = ETH_ADDR[0] if datapath.id == 1 else ETH_ADDR[1]
                #         match = ofp_parser.OFPMatch(eth_dst=eth_dst)
                #         # port = 4 if datapath.id == 1 else 3
                #         port = 1
                #         actions = [ofp_parser.OFPActionOutput(port)]
                #         print 'datapath.id == 1,in _state_change_handler'
                #         self.add_flow(datapath, 1, match, actions)

                #         # in case of there's no flows in first 20s
                #         match = ofp_parser.OFPMatch(in_port=1)
                #         actions = [ofp_parser.OFPActionOutput(2)]
                #         self.add_flow(datapath, 1, match, actions, SLEEP_PERIOD)

                #         # send eth_dst==ETHERNET_MULTICAST packages to controller
                #         match = ofp_parser.OFPMatch(eth_dst=ETHERNET_MULTICAST)
                #         actions = [ofp_parser.OFPActionOutput(
                #             ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
                #         self.add_flow(datapath, 1, match, actions)
                #     elif datapath.id == 6 or datapath.id == 8:
                #         match = ofp_parser.OFPMatch(in_port=1)
                #         actions = [ofp_parser.OFPActionOutput(2)]
                #         self.add_flow(datapath, 1, match, actions)

                #         match = ofp_parser.OFPMatch(in_port=2)
                #         actions = [ofp_parser.OFPActionOutput(1)]
                #         self.add_flow(datapath, 1, match, actions)

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                # self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # global multipath_controller_enable
        # if multipath_controller_enable == False:
        #     return
        if multipath_controller_enable == True:
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

            header_list = dict(
                (p.protocol_name, p) for p in pkt.protocols if type(p) != str)

            # avoid broadcast from ipv6 or LLDP
            if IPV6 in header_list or eth.ethertype == 35020:
                out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                    in_port=in_port, actions=[], data=None)
                datapath.send_msg(out)
                return

            if ARP in header_list:
                self.arp_table[header_list[ARP].src_ip] = src  # ARP learning
                # print "ARP"

            self.mac_to_port.setdefault(dpid, {})
            # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
            # print "\npacket in %s %s %s %s" % (dpid, src, dst, in_port)

            # learn a mac address to avoid FLOOD next time.fg  
            self.mac_to_port[dpid][src] = in_port

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                if self.arp_handler(header_list, datapath, in_port, msg.buffer_id):
                    # 1:reply or drop;  0: flood
                    # print "ARP_PROXY_13"
                    return None
                else:
                    out_port = ofproto.OFPP_FLOOD
                    # print self.sw
                    # print 'OFPP_FLOOD'

            actions = [parser.OFPActionOutput(out_port)]

            # if multipath_controller_enable == False:
            #     return
            self.send_packet_out(msg, actions)
    def arp_handler(self, header_list, datapath, in_port, msg_buffer_id):
        header_list = header_list
        datapath = datapath
        in_port = in_port
        # global multipath_controller_enable


        if ETHERNET in header_list:
            eth_dst = header_list[ETHERNET].dst
            eth_src = header_list[ETHERNET].src

        if eth_dst == ETHERNET_MULTICAST and ARP in header_list:
            arp_dst_ip = header_list[ARP].dst_ip
            if (datapath.id, eth_src, arp_dst_ip) in self.sw:  # Break the loop
                if self.sw[(datapath.id, eth_src, arp_dst_ip)] != in_port:
                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                        in_port=in_port,
                        actions=[], data=None)
                    datapath.send_msg(out)
                    # del self.sw[(datapath.id, eth_src, arp_dst_ip)]
                    print "**** drop ****"
                    return True
            else:
                self.sw[(datapath.id, eth_src, arp_dst_ip)] = in_port

        if ARP in header_list:
            opcode = header_list[ARP].opcode

            arp_src_ip = header_list[ARP].src_ip
            arp_dst_ip = header_list[ARP].dst_ip

            actions = []

            if opcode == arp.ARP_REQUEST:
                if arp_dst_ip in self.arp_table:  # arp reply
                    actions.append(
                        datapath.ofproto_parser.OFPActionOutput(in_port))

                    ARP_Reply = packet.Packet()
                    ARP_Reply.add_protocol(ethernet.ethernet(
                        ethertype=header_list[ETHERNET].ethertype, dst=eth_src,
                        src=self.arp_table[arp_dst_ip]))
                    ARP_Reply.add_protocol(arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=self.arp_table[arp_dst_ip], src_ip=arp_dst_ip,
                        dst_mac=eth_src, dst_ip=arp_src_ip))

                    ARP_Reply.serialize()

                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                        in_port=datapath.ofproto.OFPP_CONTROLLER,
                        actions=actions, data=ARP_Reply.data)
                    datapath.send_msg(out)
                    return True
        # print "flase"
        return False

    def add_flow(self, dp, p, match, actions, hard_timeout=0, buffer_id=None):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=dp, priority=p, match=match, instructions=inst,
                idle_timeout=0, hard_timeout=hard_timeout, buffer_id=buffer_id)
        else:
            mod = parser.OFPFlowMod(
                datapath=dp, priority=p, match=match, instructions=inst,
                idle_timeout=0, hard_timeout=hard_timeout)
        # print 'add_flow has been used'
        dp.send_msg(mod)

    def send_packet_out(self, msg, actions):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
