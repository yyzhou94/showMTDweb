# -*- coding: utf-8 -*-
"""
Author: gztsoul
Time: 2016/11/04 14:30
License: GZT LICENSE
Introduction:
        在该部分，分为两种情况：1、在LLTD中，隐藏主机；2、合并交换机
        1、隐藏主机的策略，对于每一台主机，都有脆弱性（VUL）和重要性（IMP）
            两个参数，根据这两个参数，对主机进行拓扑发现阶段的隐藏，
            为了体现MTD的策略，该算法中通过一台主机隐藏的次数和所有的时间周期的比值取负，
            对主机隐藏与否进行调控，即主机隐藏策略公式化为：
               hide ~~ (1-n/N)*(vul_factor*VUL + imp_factor*IMP)
               然后隐藏value排在前50%的主机。

        2、合并交换机的策略，根据交换机上连接的隐藏主机，计算该交换机上隐藏主机的
            隐藏概率之和，取前50%进行合并。
            注： 所谓合并，就是使交换机显示为集线器。
                隐藏主机的百分比和合并交换机的百分比是可调节的参数。

        3、正如我所预料的一样，所有的LLTD数据包全部是发给控制器，并没有在OF交换机上匹配下发的
          LLTD匹配项，但是，最终却能产生一个貌似正确的结果，这值得去考虑，需要仔细的去考虑。

        2016/11/09
        1、网络的移动问题： 每台主机算出评分之后，已经确定它处在的位置，动态改变是否有必要，
              改变会增加网络的成本；
        2、局域网中重要的机器是否只占用很少的一部分(无法作假设)
             没有特别大的改变，机器的重要性和健壮性是不发生变化的。
             未讨论出该假设的意义。

        3、根据重要性(I)和健壮性(S)对主机进行调控,最终评分(P)：
            P ~~~   k * (a*I + b*S)
            此时，根据（1、）中结果，网络移动问题的调控参数k有没有调节的必要？
            显然，评分高的主机有更高的可能性在线。

        4、那么，交换机的评分如何去求？
           根据网络中连接该交换机的所有主机的评分进行计算（求和，期望，其他），然后根据评分结果
           进行隐藏。

        5、重要性评价，根据主机对局域网提供的服务，确定主机的重要性。
           局域网内的服务，切记。


"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import hub

import lltd_parse
import host_info
import time

# 代表hosts的脆弱性和重要性
# [(dpid, mac_addr, vul, imp)]
ETH_TYPE_LLTD = 0x88d9
TOPO_HOSTS = host_info.topology_hosts_info
TOPO_CHANGE_PERIOD = 60
VUL_FACTOR = 0.5
IMP_FACTOR = 0.5
topo_disco_enable = False
START_MTD = False

# 隐藏的主机百分比和合并的交换机的百分比
hosts_hide_percent = 0.5
switches_merge_percent = 0.5


class TopologyDiscover(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TopologyDiscover, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.period = 0
        self.hosts_hide_nums = {tup[1]:0 for tup in TOPO_HOSTS}
        self.hided_host = None        # [(dpid, MAC, value)]
        self.merged_switches = None       # [dpid]
        self._topo_change_thread = hub.spawn(self._topo_change)

    def _topo_change(self):
        while True:
            # topolopy discover hide hosts
            # 按照逻辑，del_merged_switches_entries就会把合并的交换机上的LLTD流表全部清空，
            # 包括隐藏主机的流表项和合并交换机的流表项，
            # del_hided_host_entries用来清空未合并的交换机上的流表项
            # self.del_merged_switches_entries(self.merged_switches)
            # self.del_hided_host_entries(self.hided_host)
            if START_MTD == True:
                print '**********TOPO CHANGE**********'
                self.del_lltd_flow_entries()
                # hub.sleep(20)

                self.period += 1
                hide_hosts = self.calc_topo_disco_hide_hosts(TOPO_HOSTS, VUL_FACTOR, IMP_FACTOR)
                print hide_hosts
                self.hided_host = hide_hosts
                for ele in hide_hosts:
                    self.hosts_hide_nums[ele[1]] += 1
                self.topo_discover_hide_hosts(hide_hosts)

                # topolopy discover merge switches
                merge_switches = self.calc_topo_disco_merge_switches(hide_hosts)
                print merge_switches
                self.merged_switches = merge_switches
                print '**********TOPO CHANGE**********'
                # self.topo_discover_merge_switches(merge_switches)
            if START_MTD == False:
                print '*******************init topo*******************'
                self.del_lltd_flow_entries()
                self.merged_switches = None
                self.del_hided_host_entries(self.hided_host)
                print '*******************init topo*******************'
            hub.sleep(TOPO_CHANGE_PERIOD)


    def calc_topo_disco_hide_hosts(self, topo_hosts, vul_factor, imp_factor):
        """
            Calculate hide hosts, struction [(dpid, MAC, value)]
            it hide half of hosts
        """
        hide_prob = [(item[0], item[1], (1-self.hosts_hide_nums[item[1]]*1.0/self.period)*(vul_factor*item[2]+imp_factor*item[3]))
                        for item in topo_hosts]
        sorted_hide_prob = sorted(hide_prob, key=lambda ele:ele[2])
        return sorted_hide_prob[int(len(sorted_hide_prob)*hosts_hide_percent):]

    def calc_topo_disco_merge_switches(self, hide_hosts):
        """
            calculate merge switches, struction [dpid]
            half of hide hosts' switches
        """
        switch_points = {}  # {dpid: value}
        for item in hide_hosts:
            switch_points.setdefault(item[0], 0)
            switch_points[item[0]] += item[2]
        sorted_switch_points = sorted(switch_points.iteritems(), key=lambda ele: ele[1])
        sorted_dpid =[tup[0] for tup in sorted_switch_points]
        return sorted_dpid[int(len(sorted_dpid)*switches_merge_percent):]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.logger.info('switch:%s connected', datapath.id)

        if datapath.id == 8:
            return
        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 1, match, actions)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        # in this, ev has no attribute msg
        print 'in function state change'
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]


    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        # print "i'm in topo packet in"
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

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        self.mac_to_port[dpid][src] = in_port
        if topo_disco_enable == True:

            # 交换机会记录mac_to_port,但集线器不会，所以让合并的交换机不记录，当作集线器
            # 隐藏交换机列表不存在，或存在，但是dpid不在列表中
            if ((not self.merged_switches) or (self.merged_switches and dpid not in self.merged_switches)) and dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]

            # 该处代码没看懂
            # if dpid == 1 or (src != '10:00:00:00:00:01' and in_port==out_port):
            #     next = True
            # else:
            #     next = False
            # next = True
            # if topo_disco_enable == True:
            # if eth.ethertype == 0x88d9 and next:
            if eth.ethertype == 0x88d9:
                lltd_parse.lltd_parse(msg)
                print 'lltd parse'

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

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)


            ###############lpy and other ###############
            # install a flow to avoid packet_in next time
            # if out_port != ofproto.OFPP_FLOOD:
            #     match = parser.OFPMatch(eth_type=0x88d9, in_port=in_port, eth_dst=dst)
            #     # verify if we have a valid buffer_id, if yes avoid to send both
            #     # flow_mod & packet_out
            #     if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            #         self.add_flow(datapath, 1, match, actions, msg.buffer_id)
            #         return
            #     else:
            #         self.add_flow(datapath, 1, match, actions)

            # data = None
            # if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            #     data = msg.data

            # out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
            #                           in_port=in_port, actions=actions, data=data)
            # datapath.send_msg(out)

    def topo_discover_merge_switches(self, dpids):
        """
            dpids = [dpid, dpid]
        """
        for dpid in dpids:
            datapath = self.datapaths[dpid]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(eth_type=0x88d9)
            # match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            self.add_flow(datapath, 6, match, actions)

    def del_merged_switches_entries(self, dpids):
        if not dpids:
            return
        for dpid in dpids:
            datapath = self.datapaths[dpid]
            match = datapath.ofproto_parser.OFPMatch(eth_type=0x88d9)
            self.del_flow(datapath, match)

    def topo_discover_hide_hosts(self, hosts):
        """
            Add flow to hide hosts.
            hosts = [(dpid, mac, value)]
        """
        for item in hosts:
            if item[0] in self.datapaths:
                datapath = self.datapaths[item[0]]
                match = datapath.ofproto_parser.OFPMatch(eth_type=0x88d9, eth_src=item[1])
                actions = []
                self.add_flow(datapath, 10, match, actions)

    def del_hided_host_entries(self, hosts):
        """
            in every period ,delete hided hosts table entries.
            hosts = [(dpid, MAC, value)]
        """
        if not hosts:
            return
        for item in hosts:
            if item[0] in self.datapaths:
                datapath = self.datapaths[item[0]]
                match = datapath.ofproto_parser.OFPMatch(eth_type=0x88d9, eth_src=item[1])
                self.del_flow(datapath, match)

    def del_lltd_flow_entries(self):
        for dpid in self.datapaths:
            datapath = self.datapaths[dpid]
            match = datapath.ofproto_parser.OFPMatch(eth_type=0x88d9)
            self.del_flow(datapath, match)

