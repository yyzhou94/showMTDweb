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


    2016/11/09
    1、服务器端支持平台MTD，即在服务器端支持不同的操作系统和web服务器的组合（apache，tomcat）对应同一种服务，那么返回的
       结果必然能够支持正常的用户请求；但是，对于想要获取指纹信息的恶意请求者来说，必然无法获得准确的指纹（OS和Web server）。

    2、如果上述条件不满足，即只有一台机器提供服务，另一台是混淆机器，那么，在客户机访问服务的时候，建立TCP的三次握手协议之后，
       在进行高层通信的时候，由于有重传机制的保证，对于发往混淆主机的服务数据包，必然会被重传到正常的服务器上，此时，
       对高层的服务本身的功能响应不会造成影响，但是，在性能上，由于过多的重传数据包，必然会对造成影响。

    3 、 ####为什么不用主机发现和端口扫描结果辅助该实验？
         主机之间的通信量强度对混淆概率的影响，，，
        通过已经获取的信息，即主机通信的频繁程度调控混淆概率，
        CONF_Pro ~~~  a x Fh + Ocon

    4、有服务的机器和其他的主机的通信比较频繁。
        P2P场景例外，

    2016、11、30
    1、由于发往混淆区的主机可能会回复RST数据包，导致连接被重置，所以阻断混淆区主机回复的RST数据包
    nc try

    2016/12/01
    当连接http服务时，由于混淆区和服务器都能进行tcp三次握手，所以只要SYN和ACK发往同一个服务器，都能建立连接，
    最有趣的情况是SYN发往服务器，ACK发往混淆区（由于混淆区无法回应RST数据包），此时将会产生很有趣的结果

    但是，HTTP请求不同，所以，经过几次刷新之后，主机还是能够获取正确的http服务;
    以后可以尝试真正的请求服务时，服务回复的具体信息；

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
from ryu.lib.packet import in_proto
from ryu.lib import snortlib
from ryu.lib.packet import icmp
import array
import conf

import datetime

ETHERNET = ethernet.ethernet.__name__
ARP = arp.arp.__name__
IPV4 = ipv4.ipv4.__name__
IPV6 = ipv6.ipv6.__name__

ATTACKER = conf.os_attacker
VICTIM = conf.os_victim
FAKE_HOST = conf.os_fake_host
OSVERSION_PRIORITY = 2
IPV6_PRIORITY = 6
DROP_RST_PRIORITY = 3
CONFUSION_PROBABILITY = conf.os_confusion_probability
SNORT_PRIORITY = 5

# 控制snort是否运行
SNORT_START = False

# 改变SNORT状态时用到的标志位
Flag = False


# 控制该模块是否运行
os_web_detect_enable = False

class OSWebVersionDetect(app_manager.RyuApp):
    OFP_VERSION = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib': snortlib.SnortLib}

    def __init__(self, *args, **kwargs):
        super(OSWebVersionDetect, self).__init__(*args, **kwargs)
        self.snort_port = 6

        self.count = 0
        # 第一位表示虚拟出的主机，第二位表示标志位
        # self.fake = (None, -1)

        # self.snort.set_config(socket_config)
        # self.snort.start_socket_server()
        self.mac_to_port = {}
        self.datapaths = {}     # {dpid: datapath}
        # self._loop_handler = hub.spawn(self._loop_print)
        self._timerout_thread = hub.spawn(self._timerout)


    def _loop_print(self):
        while True:
            hub.sleep(100)
            print self.mac_to_port
            if not self.datapaths:
                self.mac_to_port.clear()



    def packet_print(self, pkt):
        pkt = packet.Packet(array.array('B', pkt))

        eth = pkt.get_protocol(ethernet.ethernet)
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        _icmp = pkt.get_protocol(icmp.icmp)

        if _icmp:
            self.logger.info("%r", _icmp)

        if _ipv4:
            self.logger.info("%r", _ipv4)

        if eth:
            self.logger.info("%r", eth)




    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
        global SNORT_START
        if SNORT_START == True and os_web_detect_enable==True:
            msg = ev.msg

            datapath = self.datapaths[1]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            if datapath.id == 1:
                    # print '######### ADD OSVersionDetect Flows #############'
                    self.send_group_mod(datapath)
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
            # 抛弃RST数据包
            match = parser.OFPMatch(eth_src=FAKE_HOST['mac'], eth_dst=ATTACKER['mac'],
                                    eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_TCP,
                                    tcp_flags=0x004)
            actions = []
            self.add_flow(datapath, DROP_RST_PRIORITY, match, actions)
            print('alertmsg: %s' % ''.join(msg.alertmsg))
            self.packet_print(msg.pkt)
            # self.fake = (FAKE_HOST, self.count)



    def _timerout(self):
        while True:
            hub.sleep(1)
            global Flag, SNORT_START
            if Flag and SNORT_START:
                print '---delete flows----'
                datapath = self.datapaths[1]
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser


                if datapath.id == 1:
                    match = parser.OFPMatch(eth_src=ATTACKER['mac'], eth_dst=VICTIM['mac'],
                                            eth_type=ether_types.ETH_TYPE_IP)
                    self.del_flow(datapath, match)

                    match = parser.OFPMatch(eth_src=FAKE_HOST['mac'], eth_dst=ATTACKER['mac'],
                                            eth_type=ether_types.ETH_TYPE_IP)
                    self.del_flow(datapath, match)


                # 清空实体SDN交换机流表并且添上新的流表
                for dpid in self.datapaths:
                    if dpid not in range(1,9):
                        dp = self.datapaths[dpid]
                        parser = dp.ofproto_parser
                        match = parser.OFPMatch()
                        self.del_flow(dp,match)
                        match = parser.OFPMatch()
                        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
                        self.add_flow(dp, 1, match, actions)

                match = parser.OFPMatch(eth_src=FAKE_HOST['mac'], eth_dst=ATTACKER['mac'],
                                        eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_TCP,
                                        tcp_flags=0x004)
                self.del_flow(datapath, match)

                Flag = False
                SNORT_START = False

                # self.fake = (None,-1)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_feature_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # ignore loop
        if datapath.id == 8:
            return
        # install group-table
        # if datapath.id == 1:
        #     self.send_group_mod(datapath,)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6)
        # actions = []
        # self.add_flow(datapath, IPV6_PRIORITY, match, actions)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        # in this, ev has no attribute msg
        print 'in function state change'
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
        if os_web_detect_enable == True:
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


            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port
            # print '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'
            # print 'dpid '+str(dpid)+' src ' +src+' in port '+str(in_port)
            # print '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            if dpid == 1:
                actions = [parser.OFPActionOutput(out_port),
                       parser.OFPActionOutput(self.snort_port)]
            else:
                # self.logger.info("dpid != 1")
                actions = [parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                if msg.buffer_id != ofproto.OFPCML_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)
            data = None
            if msg.buffer_id == ofproto.OFPCML_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        pass

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

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                    instructions=inst, buffer_id=buffer_id, hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst, hard_timeout=hard_timeout)
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

