# -*- coding: utf-8 -*-
# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

import lltd_parse
import time

from ryu.lib import hub


SLEEP_PERIOD = 4

topo_disco_enable = True
# 1. Exec `ryu-manager topo_discover4.py` to start controller
# 2. Exec `sudo python topo-discover-linear.py` to start mininet
# 3. Start Mapper in win7

class TopoDiscover(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TopoDiscover, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}


        self._addflow_thread = hub.spawn(self._addflows)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if datapath.id not in self.datapaths:
            self.logger.debug('register datapath: %016x', datapath.id)
            self.datapaths[datapath.id] = datapath

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        ########## priority=1 !!!!!!!!!!! ##########
        if datapath.id not in range(1, 9) or datapath.id != 8:
            self.add_flow(datapath, 1, match, actions)


        ########## API调用 ##########
        ########## API调用 ##########
        ########## API调用 ##########
        ########## API调用 ##########
        # hosts格式为:[(datapath.id, 主机mac地址),(datapath.id, 主机mac地址)]
        # hosts = [(2,'10:00:00:00:00:04'), (2,'10:00:00:00:00:05'), (2,'10:00:00:00:00:06'), (3,'10:00:00:00:00:09'), (3,'10:00:00:00:00:10'), (3,'10:00:00:00:00:11'), (4,'10:00:00:00:00:14'), (4,'10:00:00:00:00:15'), (4,'10:00:00:00:00:16'), (5,'10:00:00:00:00:17'), (5,'10:00:00:00:00:18'), (5,'10:00:00:00:00:19'), (5,'10:00:00:00:00:20'), (5,'10:00:00:00:00:21')]
        # self.topo_discover_hide_hosts(hosts)

    
    def _addflows(self):
        hosts = [(2,'10:00:00:00:00:04'), (2,'10:00:00:00:00:05'), (2,'10:00:00:00:00:06'), (3,'10:00:00:00:00:09'), (3,'10:00:00:00:00:10'), (3,'10:00:00:00:00:11'), (4,'10:00:00:00:00:14'), (4,'10:00:00:00:00:15'), (4,'10:00:00:00:00:16'), (5,'10:00:00:00:00:17'), (5,'10:00:00:00:00:18'), (5,'10:00:00:00:00:19'), (5,'10:00:00:00:00:20'), (5,'10:00:00:00:00:21')]
        while True:
            if topo_disco_enable == True:
                self.topo_discover_hide_hosts(hosts)

            hub.sleep(SLEEP_PERIOD)




    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        # if topo_controller_enable == False:
        #     return
        if topo_disco_enable == True:
            if ev.msg.msg_len < ev.msg.total_len:
                self.logger.debug("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)
            msg = ev.msg
            datapath = msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            in_port = msg.match['in_port']

            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocols(ethernet.ethernet)[0]

            if eth.ethertype == ether_types.ETH_TYPE_LLDP:
                # ignore lldp packet
                return
            dst = eth.dst
            src = eth.src

            dpid = datapath.id
            self.mac_to_port.setdefault(dpid, {})

            # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

            # lpy_print(dpid, dst, src, in_port, self.mac_to_port)

            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port

            ########## API调用 ##########
            ########## API调用 ##########
            ########## API调用 ##########
            ########## API调用 ##########
            self.topo_discover_merge_switches(ev, [3,4])


    # 分支合并功能函数
    # ev为ryu处理packet_in事件函数中的ev
    # dpids为要合并的交换机的datapath.id组成的list,格式为[dpid, dpid]
    def topo_discover_merge_switches(self, ev, dpids):
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

        # 交换机会记录mac_to_port，但是集线器不会，所以让dpip!=1的交换机不记录，当做集线器
        if dpid not in dpids and dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]

        # 解析LLTD报文
        if dpid == 1 or (src!='10:00:00:00:00:01' and in_port == out_port):
            next = True
        else:
            next = False
        if eth.ethertype == 0x88d9 and next:
            lltd_parse.lltd_parse(msg)
            None

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(eth_type=0x88d9, in_port=in_port, eth_dst=dst)
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

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    # 主机隐藏功能函数
    # hosts为要隐藏的主机的信息组成的list，每个元素为一个tuple，该tuple中第一个元素为该主机连接的交换机的datapath.id，该tuple中第二个元素为要隐藏主机的MAC地址
    def topo_discover_hide_hosts(self, hosts):
        print "topo_discover_hide_hosts in  "
        for item in hosts:
            # print "item in "
            # print self.datapaths
            if item[0] in self.datapaths:
                datapath = self.datapaths[item[0]]
                match = datapath.ofproto_parser.OFPMatch(eth_type=0x88d9, eth_src=item[1])
                actions = []
                self.add_flow(datapath, 2, match, actions)
                # print "add-flows success"



    # def enable_topo(self):
    #     hosts = [(2,'10:00:00:00:00:04'), (2,'10:00:00:00:00:05'), (2,'10:00:00:00:00:06'), (3,'10:00:00:00:00:09'), (3,'10:00:00:00:00:10'), (3,'10:00:00:00:00:11'), (4,'10:00:00:00:00:14'), (4,'10:00:00:00:00:15'), (4,'10:00:00:00:00:16'), (5,'10:00:00:00:00:17'), (5,'10:00:00:00:00:18'), (5,'10:00:00:00:00:19'), (5,'10:00:00:00:00:20'), (5,'10:00:00:00:00:21')]

    #     self.topo_discover_hide_hosts(hosts)
    #     print "Hello world"





def lpy_print(*args):
    for i in args:
        print args
    time.sleep(1)
