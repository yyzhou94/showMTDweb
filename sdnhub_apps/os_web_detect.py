# -*- coding: utf-8 -*-
"""
Author: gztsoul
Time: 2016/10/21 14:30
Introduction: 

注意： 组表应该是通过OFPActionGroup()进行调用
2016/10/24 
    当前已经能实现和原版本相同的效果，但是，产生了新的问题，不知道该问题是由
    主机的原因还是由其他原因造成的，
    问题描述（以ping命令为例）：
        第一次ping命令，能够下发正确的流表，
        但是，从第二次开始，ping命令不能下发正确的流表，
        即：OF交换机一直在向控制器发送数据包，控制器好像进行了处理，但是没有加入mac_to_port表

2016/11/17
    指纹识别和拓扑发现两个模块同时启动的时候，由于基础流表在openflow交换机中的优先级不同。导致了
    实验结果显示不正确。

"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ether_types
from ryu.lib import hub

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6

import datetime

ETHERNET = ethernet.ethernet.__name__
ARP = arp.arp.__name__
IPV4 = ipv4.ipv4.__name__
IPV6 = ipv6.ipv6.__name__

ATTACKER = {'ip':'10.0.0.1', 'mac':'10:00:00:00:00:01', 'port': 1}
VICTIM = {'ip':'10.0.0.2', 'mac':'10:00:00:00:00:02', 'port': 4}
FAKE_HOST = {'ip': '192.168.2.220', 'mac': '00:00:00:22:00:01', 'port': 5}
OSVERSION_PRIORITY = 3
IPV6_PRIORITY = 6
CONFUSION_PROBABILITY = 0.8
os_web_detect_enable = False

class OSWebVersionDetect(app_manager.RyuApp):
    OFP_VERSION = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(OSWebVersionDetect, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}     # {dpid: datapath}
        self.haveAdded = False
        self._loop_handler = hub.spawn(self._loop_print)

    def _loop_print(self):
        while True:
            hub.sleep(10)
            # print self.mac_to_port
            if not self.datapaths:
                self.mac_to_port.clear()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_feature_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # ignore loop
        if datapath.id == 8:
            return
        # install group-table
        if datapath.id == 1:
            self.send_group_mod(datapath)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

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

        if eth.ethertype in [ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6]:
            # ignore lldp packets, ignore ipv6 packets
            return

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # 此种方法只能进行一次，因为只有第一次ping的时候才会上传数据包
        # 此后再ping，由于已经安装流表，所以无效
        # when h1 ping h4, add flows which move  packets
        if os_web_detect_enable == True:
            if (not self.haveAdded) and src==ATTACKER['mac'] and dst=='10:00:00:00:00:04':
                if datapath.id == 1:
                    # print '######### ADD OSVersionDetect Flows #############'
                    self.send_group_mod(datapath)
                    self.haveAdded = True
                    match = parser.OFPMatch(eth_src=ATTACKER['mac'], eth_dst=VICTIM['mac'],
                                            eth_type=ether_types.ETH_TYPE_IP)
                    actions = [parser.OFPActionGroup(group_id=2)]
                    self.add_flow(datapath, OSVERSION_PRIORITY, match, actions)

                    match = parser.OFPMatch(eth_src=FAKE_HOST['mac'], eth_dst=ATTACKER['mac'],
                                            eth_type=ether_types.ETH_TYPE_IP)
                    actions = [parser.OFPActionSetField(eth_src=VICTIM['mac']),
                               parser.OFPActionSetField(ipv4_src=VICTIM['ip']),
                               parser.OFPActionOutput(ATTACKER['port'])]
                    self.add_flow(datapath, OSVERSION_PRIORITY, match, actions)

                for dpid in self.datapaths:
                    if dpid not in range(1,9):
                        dp = self.datapaths[dpid]
                        parser = dp.ofproto_parser
                        match = parser.OFPMatch()
                        self.del_flow(dp,match)
                        match = parser.OFPMatch()
                        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
                        self.add_flow(dp, 0, match, actions)

            # when h1 ping h5, delete flows which move packets
            if self.haveAdded and src==ATTACKER['mac'] and dst=='10:00:00:00:00:05':
                # print '########## DEL OSVersionDetect Flows ################'
                if datapath.id == 1:
                    self.haveAdded = False
                    match = parser.OFPMatch(eth_src=ATTACKER['mac'], eth_dst=VICTIM['mac'],
                                            eth_type=ether_types.ETH_TYPE_IP)
                    self.del_flow(datapath, match)

                    match = parser.OFPMatch(eth_src=FAKE_HOST['mac'], eth_dst=ATTACKER['mac'],
                                            eth_type=ether_types.ETH_TYPE_IP)
                    self.del_flow(datapath, match)
                for dpid in self.datapaths:
                    if dpid not in range(1,9):
                        dp = self.datapaths[dpid]
                        parser = dp.ofproto_parser
                        match = parser.OFPMatch()
                        self.del_flow(dp,match)
                        match = parser.OFPMatch()
                        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
                        self.add_flow(dp, 1, match, actions)

            # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port
            # print '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'
            # print 'dpid '+str(dpid)+' src ' +src+' in port '+str(in_port)
            # print '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                if msg.buffer_id != ofproto.OFPCML_NO_BUFFER:
                    self.add_flow(datapath, 2, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 2, match, actions)
            data = None
            if msg.buffer_id == ofproto.OFPCML_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

    def start_mtd_strategy(self):
        pass

    def stop_mtd_strategy(self):
        pass

    def send_group_mod(self, datapath):
        # 添加组表，决定是发给VICTIM还是FAKE_HOST
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        group_id = 2
        weight_1 = (1 - CONFUSION_PROBABILITY)*100
        weight_2 = CONFUSION_PROBABILITY*100
        port_1 , port_2 = VICTIM['port'], FAKE_HOST['port']
        actions_1 = [parser.OFPActionOutput(port_1)]
        actions_2 = [parser.OFPActionSetField(eth_dst=FAKE_HOST['mac']), 
                    parser.OFPActionSetField(ipv4_dst=FAKE_HOST['ip']),
                    parser.OFPActionOutput(port_2)]

        watch_port = ofproto.OFPP_ANY
        watch_group = ofproto.OFPQ_ALL

        bucket = [parser.OFPBucket(weight_1, watch_port, watch_group, actions_1),
                  parser.OFPBucket(weight_2, watch_port, watch_group, actions_2)]

        req = parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD,
                                 ofproto.OFPGT_SELECT, group_id, bucket)
        datapath.send_msg(req)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, 
                                    instructions=inst, buffer_id=buffer_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
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