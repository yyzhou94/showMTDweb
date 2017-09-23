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

from ryu.lib.packet import ipv6


from ryu.lib import hub

#     ---- 启动阶段 ----
# 1.  启动Controller
# 2.  启动Mininet `sudo mn --controller remote --topo single,4 --mac`
# 3.  Ubuntu中运行脚本 util/connect.sh
# 4.  Mininet中执行 `h1 route add -net 0/0 dev h1-eth0`
# 5.  win7的命令行中执行 `route add 10.0.0.0/24 0.0.0.0`
#     ---- 实验阶段 ----
# 6.  此时h1执行 `nmap -A 10.0.0.2 -p 80` 结果为OS: Linux  80: Apache?
# 7.  Mininet中执行 `h1 ping h3` (下发流表的触发条件)
# 8.  h1再次执行 `nmap -A 10.0.0.2 -p 80` 结果为OS: Windows  80: SimpleHTTPServer?
#     ---- 可到此结束 ----
# 9.  Mininet中执行 `h1 ping h4` (删除流表的触发条件)
# 10. h1再次执行 `nmap -A 10.0.0.2 -p 80` 结果为OS: Linux  80: Apache?
#     ---- 结束阶段 ----
#     ---- 关机或重启则不用执行以下步骤 ----
# 11. 关闭Controller Mininet
# 12. Ubuntu中运行脚本 util/disconnect.sh
# 13. win7的命令行中执行 `route delete 10.0.0.0/24`



SLEEP_PERIOD = 4

IPV6 = ipv6.ipv6.__name__

ATTACKER = {'ip': '10.0.0.1', 'mac': '10:00:00:00:00:01', 'port': 1}
VICTIM = {'ip': '10.0.0.2', 'mac': '10:00:00:00:00:02', 'port': 2}
FAKE_HOST = {'ip': '192.168.2.221', 'mac': 'f0:de:f1:3b:bc:c7', 'port': 5}
OSVERSION_PRIORITY = 2

version_controller_enable = False


class VersionDetect(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(VersionDetect, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.haveAdded = False

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.
        #match = parser.OFPMatch()
        #actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        #self.add_flow(datapath, 0, match, actions)







    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst, buffer_id=buffer_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    def del_flow(self, datapath, priority, match, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE, priority=priority, match=match, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY, buffer_id=buffer_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE, priority=priority, match=match, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch

        # if ev.msg.msg_len < ev.msg.total_len:
        #     self.logger.debug("packet truncated: only %s of %s bytes",
        #                       ev.msg.msg_len, ev.msg.total_len)

        # if version_controller_enable == False :
        #     return

        
        # print "the code has been in version packet_in"    
        msg = ev.msg
        datapath = msg.datapath
        # self.logger("the datapath is : %s",datapth)
        ofproto = datapath.ofproto
        # parser_10 = datapath.ofproto_v1_0_parser
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packets
            return
        header_list = dict( (p.protocol_name, p) for p in pkt.protocols if type(p) != str )
        if IPV6 in header_list:
            # ignore ipv6 packets
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)


        # lpy_print(dpid, dst, src, in_port, self.mac_to_port)
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port


        if version_controller_enable == True :

        # when h1 ping h3, add flows which move all packets to fake_host that are from h1 to h2
            if (not self.haveAdded) and src==ATTACKER['mac'] and dst=='10:00:00:00:00:03' and version_controller_enable == True:
                print '!!!! ADD OSVersionDetect Flows !!!!'
                self.haveAdded = True

                match = parser.OFPMatch(eth_src=ATTACKER['mac'], eth_dst=VICTIM['mac'], eth_type=ether_types.ETH_TYPE_IP)
                actions = [parser.OFPActionSetField(eth_dst=FAKE_HOST['mac']), parser.OFPActionSetField(ipv4_dst=FAKE_HOST['ip']), parser.OFPActionOutput(FAKE_HOST['port'])]
                self.add_flow(datapath, OSVERSION_PRIORITY, match, actions)

                match = parser.OFPMatch(eth_src=FAKE_HOST['mac'], eth_dst=ATTACKER['mac'], eth_type=ether_types.ETH_TYPE_IP)
                actions = [parser.OFPActionSetField(eth_src=VICTIM['mac']), parser.OFPActionSetField(ipv4_src=VICTIM['ip']), parser.OFPActionOutput(ATTACKER['port'])]
                self.add_flow(datapath, OSVERSION_PRIORITY, match, actions)

            # when h1 ping h4, delete flows which move all packets to fake_host that are from h1 to h2
            if self.haveAdded and src==ATTACKER['mac'] and dst=='10:00:00:00:00:04' and version_controller_enable == True:
                print '!!!! DEL OSVersionDetect Flows !!!!'
                self.haveAdded = False

                match = parser.OFPMatch(eth_src=ATTACKER['mac'], eth_dst=VICTIM['mac'], eth_type=ether_types.ETH_TYPE_IP)
                self.del_flow(datapath, OSVERSION_PRIORITY, match)

                match = parser.OFPMatch(eth_src=FAKE_HOST['mac'], eth_dst=ATTACKER['mac'], eth_type=ether_types.ETH_TYPE_IP)
                self.del_flow(datapath, OSVERSION_PRIORITY, match)

            
        
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(eth_src=src, eth_dst=dst)
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
