import json
import logging

import os
from ryu.base import app_manager
from ryu.app.sdnhub_apps import port_scan
from ryu.app.sdnhub_apps import os_web_detect
from ryu.app.sdnhub_apps import host_discover
from ryu.app.sdnhub_apps import multipath_choose_controller_group_table
from ryu.app.sdnhub_apps import topo_disco_controller


from webob import Response
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib import dpid as dpid_lib
from ryu.controller import dpset
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_3
from ryu.lib import ofctl_v1_0
from ryu.lib import ofctl_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import hub
import lltd_parse
import host_info
import time

from ryu.lib.packet import ipv6




simple_switch_instance_name = 'topo_disco'
url = '/simpleswitch/topo'

class TopoRest(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
            ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'wsgi': WSGIApplication ,
        # 'dpset': dpset.DPSet,
        'topo_disco':topo_disco_controller.TopologyDiscover
    }

    def __init__(self, *args, **kwargs):
        super(TopoRest, self).__init__(*args, **kwargs)
        
        wsgi = kwargs['wsgi']
        
        topo_disco = kwargs['topo_disco']
        self.waiters = {}
        self.data = {}
        
        self.data['waiters'] = self.waiters
        self.data['topo_disco'] = topo_disco



        wsgi.register(TopoController, {simple_switch_instance_name : self})

        mapper = wsgi.mapper

        mapper.connect('topo_disco', '/v1.0/disco/topo',
                       controller=TopoController, action='enable_topo_disco',
                       conditions=dict(method=['POST']))
        
    # @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    # def switch_features_handler(self, ev):
    #     super(SimpleSwitchRest13, self).switch_features_handler(ev)
    #     datapath = ev.msg.datapath
    #     self.switches[datapath.id] = datapath
    #     self.mac_to_port.setdefault(datapath.id, {})

    # def set_mac_to_port(self, dpid, entry):
    #     mac_table = self.mac_to_port.setdefault(dpid, {})
    #     datapath = self.switches.get(dpid)
    #
    #     entry_port = entry['port']
    #     entry_mac = entry['mac']
    #
    #     if datapath is not None:
    #         parser = datapath.ofproto_parser
    #         if entry_port not in mac_table.values():
    #
    #             for mac, port in mac_table.items():
    #
    #                 # from known device to new device
    #                 actions = [parser.OFPActionOutput(entry_port)]
    #                 match = parser.OFPMatch(in_port=port, eth_dst=entry_mac)
    #                 self.add_flow(datapath, 1, match, actions)
    #
    #                 # from new device to known device
    #                 actions = [parser.OFPActionOutput(port)]
    #                 match = parser.OFPMatch(in_port=entry_port, eth_dst=mac)
    #                 self.add_flow(datapath, 1, match, actions)
    #
    #             mac_table.update({entry_mac : entry_port})
    #     return mac_table

class TopoController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(TopoController, self).__init__(req, link, data, **config)
        self.topo_disco = data[simple_switch_instance_name]
        # self.dpset = data['dpset']

    def enable_topo_disco(self,req, **kwargs):
        for i in range(1,9):
            os.system("sudo ovs-ofctl del-flows  s%d" %i )
        for i in range(1,8):
            os.system("ovs-ofctl add-flow s%d priority=1,actions=CONTROLLER:65535" %i)
        topo_disco_controller.topo_disco_enable = True
        print  "topo_disco_controller.topo_disco_enable: ",topo_disco_controller.topo_disco_enable
        multipath_choose_controller_group_table.multipath_choose_enable = False
        port_scan.port_scan_enable= False
        
        host_discover.host_scan_enable = False
        os_web_detect.os_web_detect_enable = False
        return Response(status=200,content_type='application/json',
                    body=json.dumps({'status':'success'}))