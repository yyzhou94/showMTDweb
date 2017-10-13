# -*- coding: utf-8 -*-
"""
Author: gztsoul
Time: 2016/10/25 11:00
License: GZT LICENSE
        This License is compatible with the Apache License, Version 2.0 (the "License");
        you may not use this file except in compliance with the License.
        YOu may obtain a copy of the License at
        http://www.apache.org/licenses/LICENSE-2.0
Introduction:
    2016/10/28  11:00
    1、由于当前前后端交互的性质，使得无法让多个app同时运行，
        即，不能通过_CONTEXTS参数在一个app中注册其他app，所以所有的功能只能写在
        同一个app中，显得冗余繁杂，
        注：如果以后能找到解决的办法，那么就可以进行重构，分成多个app，那样会显得
            简洁明了。
    2、启动网络感知模块，需要用命令 ryu-manager [app.py] --observe-link

    3、从目的路径中可以选择多条路径，为了简单计算，此代码实现只选择两条路径。

    4、下一步目标：根据路径上的流量信息，如何定时更改流量路径信息。

    5、当处理从h1出发的流量时，在58的1端口和83的2端口也会产生h1的数据信息，
       需要额外处理。
       当第一个主机和其他主机进行通信的时候，会产生错误
       错误的原因是由于和物理OF交换机的端口连接普通交换机时，该端口不被当作连接交换机的端口。

    两个报告：关键技术描述报告， 仿真技术描述报告

    2016/11/09
    1、通过组表调控，在每一个交叉点上进行分别处理，即都添加组表

       以最简单的为例，
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import hub

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link

from ryu.lib.packet import arp, icmp, ipv4, tcp, udp

import networkx as nx
import datetime
from operator import attrgetter

ETHERNET = ethernet.ethernet.__name__
ARP = arp.arp.__name__
IPV4 = ipv4.ipv4.__name__
ETHERNET_IPV4 = ether_types.ETH_TYPE_IP

MONITOR_PERIOD = 10
MULTIPATH_PERIOD = 4
# 10MB
MAX_CAPACITY = 10000000
multipath_choose_enable = False


class MultipathChoose(app_manager.RyuApp):
    OFP_VERSION = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MultipathChoose, self).__init__(*args, **kwargs)

        self.mac_to_port = {}
        self.datapaths = {}

        # network_awareness module
        # 用于发现网络中的switch和Link信息
        self.topology_api_app = self
        self.link_to_port = {}                #  (src_dpid, dst_dpid) --> (src_port, dst_port)
        self.access_table = {}                #  {(sw,port): (host_ip, mac)}
        self.switches = {}
        self.switch_port_table = {}           #  交换机所有LIVE的端口
        self.interior_ports = {}
        self.access_ports = {}
        self.graph = nx.DiGraph()

        self.pre_link_to_port = {}
        self.pre_access_table = {}
        self.pre_graph = nx.DiGraph()
        self.network_awareness_thread = hub.spawn(self.network_awareness)

        # network flow monitor module
        # 网络流量监控模块，用于获取各个链路的流量信息
        self.stats = {}
        self.port_stats = {}
        self.port_speed = {}
        self.flow_stats = {}                # {dpid: {(in_port,dst_ip,out_port): [value]} }
        self.flow_speed = {}
        self.free_bandwidth = {}
        self.port_features = {}
        self.capabilities = None
        self.free_bw_graph = nx.DiGraph()
        # self.best_paths = None
        self.network_monitor_thread = hub.spawn(self.network_monitor)

        # self.show_all_path_thread = hub.spawn(self.show_all_short_path)

        # 记录多路径的字典
        # self.multipath_table = {}          # {(src_ip, dst_ip):(count,[multipath])}
        # self._multipath_choose_thread = hub.spawn(self._multipath_choose)

    def _multipath_choose(self):
        while True:
            del_multipath_entries = []
            if multipath_choose_enable == True:
                for key in self.multipath_table:
                    # 判断该源和目的之间是否还有数据通信,如果没有，准备删除,<0.1
                    # gzt mark: 该处的判断逻辑还是有问题，需要进行调整
                    # src_dpid = self.get_host_location(key[0])[0]
                    # for speed_key in self.flow_speed[src_dpid]:
                    #     if (key[0] == speed_key[0]) and (key[1]==speed_key[1]):
                    #         if self.flow_speed[src_dpid][speed_key][-1] < 1:
                    #             del_multipath_entries.append(key)
                    #             print key
                    #             break
                    self.multipath_table[key][0] = (self.multipath_table[key][0]+1)%2
                    path_num = self.multipath_table[key][0]
                    path = self.multipath_table[key][1][path_num]
                    print path
                    # flow_info = (eth_type, ip_src, ip_dst, in_port)
                    # in_port == 0 代表是周期性的变换路径
                    flow_info = (ETHERNET_IPV4, key[0], key[1], 0)
                    self.install_flow(self.datapaths,
                                      self.link_to_port,
                                      self.access_table, path,
                                      flow_info)
                # 删除速度为0的条目
                for entry in del_multipath_entries:
                    del self.multipath_table[entry]
            hub.sleep(MULTIPATH_PERIOD)

    def show_all_short_path(self):
        while True:
            print 'In show all short path'
            print self.graph
            if self.graph:
                print self.graph
                for i in self.graph.nodes():
                    for j in self.graph.nodes():
                        if i != j:
                            print i,j
                            for path in self.calculate_path(i, j):
                                print path
            hub.sleep(10)

    def network_awareness(self):
        while True:
            hub.sleep(10)
            self.get_topology(None)
            # print self.switch_port_table
            # self.show_topology()
            # if self.port_features:
            #     print self.port_features


    events = [event.EventSwitchEnter, event.EventSwitchLeave,
              event.EventPortAdd, event.EventPortDelete,
              event.EventPortModify, event.EventLinkAdd,
              event.EventLinkDelete]

    @set_ev_cls(events)
    def get_topology(self, ev):
        switch_list = get_switch(self.topology_api_app, None)
        # for sw in switch_list:
        #     print sw.dp.id
        #     for port in sw.ports:
        #         print port

        self.create_port_map(switch_list)
        self.switches = self.switch_port_table.keys()
        link_list = get_link(self.topology_api_app, None)
        # for link in link_list:
        #     print link
        self.create_interior_links(link_list)
        self.create_access_ports()
        self.generate_graph(self.link_to_port.keys())

    def get_host_location(self, host_ip):
        for key in self.access_table:
            if self.access_table[key][0] == host_ip:
                return key
        self.logger.info("%s location is not found." % host_ip)
        return None

    def create_port_map(self, switch_list):
        """
        Create interior_port table and access_port table
        """
        for switch in switch_list:
            dpid = switch.dp.id
            self.switch_port_table.setdefault(dpid, set() )
            self.interior_ports.setdefault(dpid, set() )
            self.access_ports.setdefault(dpid, set() )

            for port in switch.ports:
                if port.is_live():
                    self.switch_port_table[dpid].add(port.port_no)

    def create_interior_links(self, link_list):
        """
            Get links`srouce port to dst port  from link_list,
            link_to_port:(src_dpid,dst_dpid)->(src_port,dst_port)
            6790944927334401058, 1
            6790944927334400383, 2
            TO-DO
            TO-DO
            TO-DO
            上面两个端口由于和普通交换机连接，会使结果产生错误，
            下面为最简单的解决方法,有更好的方法可以再进行尝试
        """
        # gzt mark: 简单解决办法
        # switch_port_1 = (6790944927334401058, 1)
        # switch_port_2 = (6790944927334400383, 2)
        # if (switch_port_1[0] in self.switches and switch_port_2[0] in self.switches):
        #     # print '*************deal with normal switch*****************'
        #     self.link_to_port[(switch_port_1[0], switch_port_2[0])] = (switch_port_1[1], switch_port_2[1])
        #     self.link_to_port[(switch_port_2[0], switch_port_1[0])] = (switch_port_2[1], switch_port_1[1])
        #     self.interior_ports[switch_port_1[0]].add(switch_port_1[1])
        #     self.interior_ports[switch_port_2[0]].add(switch_port_2[1])


        for link in link_list:
            src = link.src
            dst = link.dst
            self.link_to_port[
                (src.dpid, dst.dpid)] = (src.port_no, dst.port_no)

            # Find the access ports and interiorior ports
            if link.src.dpid in self.switches:
                self.interior_ports[link.src.dpid].add(link.src.port_no)
            if link.dst.dpid in self.switches:
                self.interior_ports[link.dst.dpid].add(link.dst.port_no)

    def create_access_ports(self):
        """
            Get ports without link into access_ports
        """
        for sw in self.switch_port_table:
            all_port_table = self.switch_port_table[sw]
            interior_port = self.interior_ports[sw]
            self.access_ports[sw] = all_port_table - interior_port

    def generate_graph(self, edge_list):
        """
            Get Adjacency matrix from link_to_port
        """
        for src in self.switches:
            for dst in self.switches:
                # self.graph.add_edge(src, dst, weight=float('inf'))
                if src == dst:
                    self.graph.add_edge(src, dst, weight=0)
                elif (src, dst) in edge_list:
                    self.graph.add_edge(src, dst, weight=1)
        return self.graph

    def show_topology(self):
        switch_num = len(self.graph.nodes())
        print '---------------------Topo Link---------------------'
        print '%10s' % ('switch'),
        for i in self.graph.nodes():
            i1 = i if i<20 else i%100
            print '%5d' % i1,
        print
        for i in self.graph.nodes():
            i1 = i if i<20 else i%100
            print '%10d' % i1,
            for j in self.graph.nodes():
                if j in self.graph[i]:
                    print '%5.0f' % self.graph[i][j]['weight'],
                else:
                    print '%5s' %('*'),
            print




    def network_monitor(self):
        while True:
            self.stats['flow'] = {}
            self.stats['port'] = {}
            for dp in self.datapaths.values():
                self.port_features.setdefault(dp.id, {})
                self._request_stats(dp)
            hub.sleep(MONITOR_PERIOD)
            self.free_bw_graph = self.create_bw_graph(self.free_bandwidth)
            self.logger.debug('Save free bandwidth graph')
            print self.flow_speed

    def _request_stats(self, datapath):
        """
            Sending request msg to datapath
        """
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # request port description info
        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

        # request port stats request
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

        # request flow stats request
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def _save_freebandwidth(self, dpid, port_no, speed):
        # Calculate free bandwidth of port and save it.
        port_state = self.port_features.get(dpid).get(port_no)
        if port_state:
            capacity = port_state[2]
            curr_bw = self._get_free_bw(capacity, speed)
            self.free_bandwidth[dpid].setdefault(port_no, None)
            self.free_bandwidth[dpid][port_no] = curr_bw
        else:
            self.logger.info("Fail in getting port state")

    def create_bw_graph(self, bw_dict):
        """
            Save bandwidth data into networkx graph object.
        """
        graph = self.graph
        link_to_port = self.link_to_port
        for link in link_to_port:
            (src_dpid, dst_dpid) = link
            (src_port, dst_port) = link_to_port[link]
            if src_dpid in bw_dict and dst_dpid in bw_dict:
                bw_src = bw_dict[src_dpid][src_port]
                bw_dst = bw_dict[dst_dpid][dst_port]
                bandwidth = min(bw_src, bw_dst)
                # add key:value of bandwidth into graph.
                graph[src_dpid][dst_dpid]['bandwidth'] = bandwidth
            else:
                graph[src_dpid][dst_dpid]['bandwidth'] = 0
        return graph


    def _get_free_bw(self, capacity, speed):
        # BW:Mbit/s
        return max(capacity/10**3 - speed*8, 0)

    def _save_stats(self, _dict, key, value, length):
        if key not in _dict:
            _dict[key] = []
        _dict[key].append(value)

        if len(_dict[key]) > length:
            _dict[key].pop(0)

    def _get_speed(self, now, pre, period):
        if period:
            return (now - pre) / (period)
        else:
            return 0

    def _get_time(self, sec, nsec):
        return sec + nsec/(10**9)

    def _get_period(self, n_sec, n_nsec, p_sec, p_nsec):
        return self._get_time(n_sec, n_nsec) - self._get_time(p_sec, p_nsec)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        """
            save port description info.
        """
        # print 'In port desc stats'
        msg = ev.msg
        dpid = msg.datapath.id
        ofproto = msg.datapath.ofproto
        # 打印信息
        # for p in ev.msg.body:
        #     print p
        # print

        config_dict = {ofproto.OFPPC_PORT_DOWN: "Down",
                       ofproto.OFPPC_NO_RECV: "No Recv",
                       ofproto.OFPPC_NO_FWD: "No Farward",
                       ofproto.OFPPC_NO_PACKET_IN: "No Packet-in"}

        state_dict = {ofproto.OFPPS_LINK_DOWN: "Down",
                      ofproto.OFPPS_BLOCKED: "Blocked",
                      ofproto.OFPPS_LIVE: "Live"}

        for p in ev.msg.body:
            if p.config in config_dict:
                config = config_dict[p.config]
            else:
                config = "up"

            if p.state in state_dict:
                state = state_dict[p.state]
            else:
                state = "up"

            port_feature = (config, state, p.curr_speed)
            self.port_features[dpid][p.port_no] = port_feature

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        """
            Save port's stats info
            Calculate port's speed and save it.
        """
        # print 'In port stats reply'
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.stats['port'][dpid] = body
        self.free_bandwidth.setdefault(dpid, {})
        # self.logger.info("%s", dpid)

        # 打印端口信息
        # for stat in body:
        #     print stat
        # print

        for stat in sorted(body, key=attrgetter('port_no')):
            port_no = stat.port_no
            if port_no != ofproto_v1_3.OFPP_LOCAL:
                key = (dpid, port_no)
                # 发送，接收，错误
                value = (stat.tx_bytes, stat.rx_bytes, stat.rx_errors,
                         stat.duration_sec, stat.duration_nsec)

                self._save_stats(self.port_stats, key, value, 5)

                # Get port speed.
                pre = 0
                period = MONITOR_PERIOD
                tmp = self.port_stats[key]
                if len(tmp) > 1:
                    pre = tmp[-2][0] + tmp[-2][1]
                    period = self._get_period(tmp[-1][3], tmp[-1][4],
                                              tmp[-2][3], tmp[-2][4])

                speed = self._get_speed(
                    self.port_stats[key][-1][0] + self.port_stats[key][-1][1],
                    pre, period)

                self._save_stats(self.port_speed, key, speed, 5)
                self._save_freebandwidth(dpid, port_no, speed)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """
            Save flow stats reply info into self.flow_stats.
            Calculate flow speed and Save it.
        """
        # print 'In flow stats'
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.stats['flow'][dpid] = body
        self.flow_stats.setdefault(dpid, {})
        self.flow_speed.setdefault(dpid, {})
        # 打印流数据信息
        # for stat in body:
        #     print stat
        # print


        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match.get('ipv4_src'),
                                             flow.match.get('ipv4_dst'))):
            key = (stat.match.get('ipv4_src'),  stat.match.get('ipv4_dst'),
                   stat.instructions[0].actions[0].port)
            value = (stat.packet_count, stat.byte_count,
                     stat.duration_sec, stat.duration_nsec)
            self._save_stats(self.flow_stats[dpid], key, value, 5)

            # Get flow's speed.
            pre = 0
            period = MONITOR_PERIOD
            tmp = self.flow_stats[dpid][key]
            if len(tmp) > 1:
                pre = tmp[-2][1]
                period = self._get_period(tmp[-1][2], tmp[-1][3],
                                          tmp[-2][2], tmp[-2][3])

            speed = self._get_speed(self.flow_stats[dpid][key][-1][1],
                                    pre, period)

            self._save_stats(self.flow_speed[dpid], key, speed, 5)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        """
            Handle the port status changed event.
        """
        print 'in port status handler'
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no
        dpid = msg.datapath.id
        ofproto = msg.datapath.ofproto
        # print msg
        # print msg.reason

        # reason_dict = {ofproto.OFPPR_ADD: "added",
        #                ofproto.OFPPR_DELETE: "deleted",
        #                ofproto.OFPPR_MODIFY: "modified", }

        # if reason in reason_dict:

        #     print "switch%d: port %s %s" % (dpid, reason_dict[reason], port_no)
        # else:
        #     print "switch%d: Illeagal port state %s %s" % (port_no, reason)





    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.logger.info('switch: %s connected', datapath.id)

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)


    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        print 'in function state change'
        print datetime.datetime.now()
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
        msg = ev.msg
        datapath = msg.datapath

        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id
        pkt = packet.Packet(msg.data)

        header_list = dict(
                    (p.protocol_name, p) for p in pkt.protocols if type(p)!=str)
        if multipath_choose_enable == True:
            if ARP in header_list:
                arp_src_ip = header_list[ARP].src_ip
                arp_dst_ip = header_list[ARP].dst_ip
                mac = header_list[ARP].src_mac
                self.register_access_info(dpid, in_port, arp_src_ip, mac)
                print self.access_table
                self.logger.debug("ARP processing")
                self.arp_forwarding(msg, arp_src_ip, arp_dst_ip)

            elif IPV4 in header_list:
                # TO-DO, 进行ipv4的数据包处理
                # 此时，可以根据既定的策略进行处理，
                # 处理逻辑在该处
                self.shortest_forwarding(msg, header_list)

    def shortest_forwarding(self, msg, header_list):
        """
            To calculate shortest forwarding path and
            install them into datapaths.
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        eth_type = header_list[ETHERNET].ethertype
        ip_src = header_list[IPV4].src
        ip_dst = header_list[IPV4].dst
        src_location = self.get_host_location(ip_src)
        # 判断数据包是否是从与主机相连的OF交换机发来的
        if (datapath.id,in_port) != src_location:
            return
        src_dst_sw = self.get_sw(datapath.id, in_port, ip_src, ip_dst)
        if src_dst_sw:
            (src_sw, dst_sw) = src_dst_sw
            if dst_sw:
                # get path,
                # gzt mark: 该处的路径计算还不完善，有可能存在没有路径的情况存在
                #       需要测试一下确定
                # paths 应该为list的list
                paths = ([[src_sw]] if src_sw==dst_sw
                                else [path for path in self.calculate_path(src_sw, dst_sw)])
                print datapath.id, in_port, ip_src, ip_dst
                self.logger.info('[PATH]%s<-->%s: %s' %(ip_src, ip_dst, paths) )
                flow_info = (eth_type, ip_src, ip_dst, in_port)
                # install flow entries to datapath along side the path.
                choose_paths = self.get_appropriate_paths_by_bw(self.free_bandwidth, paths)

                self.install_flow(self.datapaths,
                                  self.link_to_port,
                                  self.access_table, choose_paths,
                                  flow_info, msg.buffer_id, msg.data)

    def install_flow(self, datapaths, link_to_port, access_table, paths,
                     flow_info, buffer_id=None, data=None):
        """
            Install flow entires for roundtrip: go and back.
            @parameter: path=[dpid1,dpid2,...]
            flow_info = (eth_type, ip_src, ip_dst, in_port)
        """
        if paths is None or len(paths) == 0:
            self.logger.info('No one path!')
            return
        if len(paths) == 1:
            path = paths[0]
            in_port = flow_info[3]
            back_info = (flow_info[0], flow_info[2], flow_info[1])
            # 安装流表，不包括第一个OF交换机返回源主机和最后一个OF交换机发送给目的。
            for i in xrange(0, len(path)-1):
                port = self.get_port_pair_from_link(link_to_port, path[i], path[i+1])
                if port:
                    src_port, dst_port = port[0], port[1]
                    self.send_flow_mod(datapaths[path[i]], flow_info, src_port)
                    self.send_flow_mod(datapaths[path[i+1]], back_info, dst_port)
                    self.logger.debug('inter_link flow install')
            # 在第一个OF交换机安装返回流表，在最后一个OF安装发给目的流表。
            src_ip_port = self.get_port(flow_info[1], access_table)
            dst_ip_port = self.get_port(flow_info[2], access_table)
            if src_ip_port is None:
                self.logger.info('port not found in first hop.')
                return
            if dst_ip_port is None:
                self.logger.info('port not found in last hop.')
                return
            self.send_flow_mod(datapaths[path[0]], back_info, src_ip_port)
            self.send_flow_mod(datapaths[path[-1]], flow_info, dst_ip_port)

            # 对于上传控制器的包，如果需要下发匹配，则出端口为out_port
            print '*********in install fuction ************'
            out_port = (self.get_port(flow_info[2], access_table) if len(path) == 1
                        else self.get_port_pair_from_link(link_to_port, path[0], path[1])[0] )
            print out_port
            self.send_packet_out(datapaths[path[0]], buffer_id, in_port, out_port, data)
            print 'after send packet out'

        # 该处为了简化运算，认为只有两条路径可供选择。
        if len(paths) > 1:
            for path in paths:
                in_port = flow_info[3]
                back_info = (flow_info[0], flow_info[2], flow_info[1])
                # 安装流表，不包括第一个OF交换机返回源主机和最后一个OF交换机发送给目的。
                for i in xrange(0, len(path)-1):
                    port = self.get_port_pair_from_link(link_to_port, path[i], path[i+1])
                    if port:
                        src_port, dst_port = port[0], port[1]
                        self.send_flow_mod(datapaths[path[i]], flow_info, src_port)
                        self.send_flow_mod(datapaths[path[i+1]], back_info, dst_port)
                        self.logger.debug('inter_link flow install')
                # 在第一个OF交换机安装返回流表，在最后一个OF安装发给目的流表。
                src_ip_port = self.get_port(flow_info[1], access_table)
                dst_ip_port = self.get_port(flow_info[2], access_table)
                if src_ip_port is None:
                    self.logger.info('port not found in first hop.')
                    return
                if dst_ip_port is None:
                    self.logger.info('port not found in last hop.')
                    return
                self.send_flow_mod(datapaths[path[0]], back_info, src_ip_port)
                self.send_flow_mod(datapaths[path[-1]], flow_info, dst_ip_port)

            # 对于dpid=1 上的从端口[1,4,5]端口进入的数据包，都进行组1处理，
            # 对于dpid=7 上从端口[1]进入的数据包，都进行组7处理
            # 组的处理是把数据包从【2,3】端口传出去
            # 该处还存在问题，需要解决
            # TO-DO : gzt mark:
            # Add by junjie: 提前預知了目的mac，有點取巧了
            if 1 in paths[0] and 7 in paths[0]:
                dp_1 = datapaths[1]
                ofproto = dp_1.ofproto
                parser = dp_1.ofproto_parser
                self.send_group_mod(dp_1, 1, [2,3])
                match = parser.OFPMatch(in_port=1, eth_dst='10:00:00:00:00:22')
                actions = [parser.OFPActionGroup(group_id=1)]
                self.add_flow(dp_1, 10, match, actions)
                match = parser.OFPMatch(in_port=4, eth_dst='10:00:00:00:00:22')
                self.add_flow(dp_1, 10, match, actions)
                match = parser.OFPMatch(in_port=5, eth_dst='10:00:00:00:00:22')
                self.add_flow(dp_1, 10, match, actions)

                dp_7 = datapaths[7]
                ofproto = dp_7.ofproto
                parser = dp_7.ofproto_parser
                self.send_group_mod(dp_7, 7, [2,3])
                match = parser.OFPMatch(in_port=1)
                actions = [parser.OFPActionGroup(group_id=7)]
                self.add_flow(dp_7, 10, match, actions)

            # 对于上传控制器的包，如果需要下发匹配，则出端口为out_port
            print '*********in install fuction ************'
            out_port = (self.get_port(flow_info[2], access_table) if len(paths[0]) == 1
                        else self.get_port_pair_from_link(link_to_port, paths[0][0], paths[0][1])[0] )
            print out_port
            self.send_packet_out(datapaths[paths[0][0]], buffer_id, in_port, out_port, data)
            print 'after send packet out'

    def send_flow_mod(self, datapath, flow_info, port):
        """
            Build flow entry, and send it to datapath.
        """
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(port)]
        match = parser.OFPMatch(
                    eth_type=flow_info[0],
                    ipv4_src=flow_info[1],
                    ipv4_dst=flow_info[2])
        self.add_flow(datapath, 1, match, actions,
                      )

    def send_packet_out(self, datapath, buffer_id, in_port, out_port, data):
        """
            Send packet out packet to assigned datapaht.
        """

        out = self._build_packet_out(datapath, buffer_id,
                                     in_port, out_port, data)
        if out:
            datapath.send_msg(out)

    def get_port(self, dst_ip, access_table):
        """
            Get access port if dst host.
            access_table: {(sw,port) :(ip, mac)}
        """
        if access_table:
            if isinstance(access_table.values()[0], tuple):
                for key in access_table.keys():
                    if dst_ip == access_table[key][0]:
                        dst_port = key[1]
                        return dst_port
        return None

    def get_port_pair_from_link(self, link_to_port, src_dpid, dst_dpid):
        """
            Get port pair of link, so that controller can install flow entry.
        """
        if (src_dpid, dst_dpid) in link_to_port:
            return link_to_port[(src_dpid, dst_dpid)]
        else:
            self.logger.info("dpid:%s->dpid:%s is not in links" % (
                             src_dpid, dst_dpid))
            return None


    def get_appropriate_paths_by_bw(self, bw_dict, paths):
        """
            Get appropriate paths for transmission
        """
        if len(paths) <= 2:
            return paths
        else:
            max_bw_of_path = 0
            max_path_pos = 0
            second_max_bw_of_path = 0
            second_max_path_pos = 0
            count = 0
            for path in paths:
                min_bw = MAX_CAPACITY
                min_bw = self.get_min_bw_of_links(self.free_bw_graph, path, min_bw)
                if min_bw > max_bw_of_path:
                    second_max_bw_of_path = max_bw_of_path
                    second_max_path_pos = max_path_pos
                    max_bw_of_path = min_bw
                    max_path_pos = count
                elif min_bw > second_max_bw_of_path:
                    second_max_bw_of_path = min_bw
                    second_max_path_pos = count
                count += 1
            choose_paths = []
            choose_paths.append(paths[max_path_pos])
            choose_paths.append(paths[second_max_path_pos])
            return choose_paths

    def get_min_bw_of_links(self, graph, path, min_bw):
        """
            Getting bandwidth of path. Actually, the mininum bandwidth
            of links is the bandwith, because it is the neck bottle of path.
        """
        _len = len(path)
        if _len > 1:
            minimal_band_width = min_bw
            for i in xrange(_len-1):
                pre, curr = path[i], path[i+1]
                if 'bandwidth' in graph[pre][curr]:
                    bw = graph[pre][curr]['bandwidth']
                    minimal_band_width = min(bw, minimal_band_width)
                else:
                    continue
            return minimal_band_width
        return min_bw


    def calculate_path(self, src_sw, dst_sw):
        """
            Calculate suitable paths to transmit packets.
        """
        all_paths = nx.all_simple_paths(self.graph, src_sw, dst_sw)
        return all_paths


    def get_sw(self, dpid, in_port, src, dst):
        """
            Get pair of source and destination switches.
        """
        src_sw = dpid
        dst_sw = None

        src_location = self.get_host_location(src)
        if in_port in self.access_ports[dpid]:
            if (dpid, in_port) == src_location:
                src_sw = src_location[0]
            else:
                return None

        dst_location = self.get_host_location(dst)
        if dst_location:
            dst_sw = dst_location[0]
        else:
            return None
        return (src_sw, dst_sw)

    def arp_forwarding(self, msg, arp_ip, dst_ip):
        """
            Send ARP packet to the destination host,if the dst host record is existed,
            else, flow it to the unknow access port.
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        result = self.get_host_location(dst_ip)
        # host record in access table.
        if result:
            (dp_dst_id, out_port) = result
            #### 知道源和目的地址，根据策略进行处理。
            # TO-DO 在此处也可以做一下其他的处理，
            # 比如下发流表什么的
            datapath = self.datapaths[dp_dst_id]
            out = self._build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                         ofproto.OFPP_CONTROLLER,
                                         out_port, msg.data)
            datapath.send_msg(out)
            self.logger.debug('Reply ARP to knew host')
        else:
            self.flood(msg)

    def flood(self, msg):
        """
            Flood ARP packet to the access port
            which has no record of host.
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dpid in self.access_ports:
            for port in self.access_ports[dpid]:
                if (dpid, port) not in self.access_table.keys():
                    datapath = self.datapaths[dpid]
                    out = self._build_packet_out(
                            datapath, ofproto.OFP_NO_BUFFER,
                            ofproto.OFPP_CONTROLLER, port, msg.data)
                    datapath.send_msg(out)
        self.logger.debug('Flooding msg')

    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Build packet out object.
        """
        actions = []
        if dst_port:
            actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port))

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            in_port=src_port, actions=actions, data=msg_data)
        return out

    def register_access_info(self, dpid, in_port, ip, mac):
        if in_port in self.access_ports[dpid]:
            if (dpid, in_port) in self.access_table:
                if self.access_table[(dpid, in_port)] == (ip, mac):
                    return
                else:
                    self.access_table[(dpid, in_port)] = (ip, mac)
                    return
            else:
                self.access_table.setdefault( (dpid, in_port), None)
                self.access_table[(dpid, in_port)] = (ip, mac)
                return

    def add_flow(self, dp, p, match, actions, idle_timeout=0, hard_timeout=0, buffer_id=None):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=dp, priority=p, match=match, instructions=inst,
                idle_timeout=idle_timeout, hard_timeout=hard_timeout, buffer_id=buffer_id)
        else:
            mod = parser.OFPFlowMod(
                datapath=dp, priority=p, match=match, instructions=inst,
                idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        dp.send_msg(mod)

    def send_group_mod(self, datapath, group_id, ports):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        group_id = group_id
        bucket = []
        for port in ports:
            actions = [parser.OFPActionOutput(port)]
            weight = 50
            watch_port = ofproto.OFPP_ANY
            watch_group = ofproto.OFPQ_ALL
            bucket.append(parser.OFPBucket(weight, watch_port, watch_group, actions))

        req = parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD,
                                 ofproto.OFPGT_SELECT, group_id, bucket)
        datapath.send_msg(req)
