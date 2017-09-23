import json
import logging

import os

from webob import Response
from ryu.base import app_manager
from ryu.app.sdnhub_apps import multipath_controller
from ryu.app.sdnhub_apps import host_port_controller
from ryu.app.sdnhub_apps import topo_controller
from ryu.app.sdnhub_apps import version_controller
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

from ryu.lib.packet import ipv6


simple_switch_instance_name = 'version_controller'
url = '/simpleswitch/version'

class VersionDetectRest(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
            ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'wsgi': WSGIApplication ,
        # 'dpset': dpset.DPSet,
        'version_controller':version_controller.VersionDetect
    }

    def __init__(self, *args, **kwargs):
        super(VersionDetectRest, self).__init__(*args, **kwargs)
        self.switches = {}
        wsgi = kwargs['wsgi']
        # dpset = kwargs['dpset']
        version_controller = kwargs['version_controller']
        self.waiters = {}
        self.data = {}
        # self.data['dpset'] = dpset
        self.data['waiters'] = self.waiters
        self.data['version_controller'] = version_controller



        wsgi.register(VersionDetectController, {simple_switch_instance_name : self})

        mapper = wsgi.mapper


        mapper.connect('version', '/v1.0/version/turnon',
                       controller=VersionDetectController, action='enable_version',
                       conditions=dict(method=['POST']))

        # mapper.connect('version_controller', '/simpleswitch/version',
        #                controller=SimpleSwitchController, action='start_test',
        #                conditions=dict(method=['POST']))

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

class VersionDetectController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(VersionDetectController, self).__init__(req, link, data, **config)
        self.version_controller = data[simple_switch_instance_name]
        # self.dpset = data['dpset']

    # def start_test():
    #     from all_mininet import  test  
    #     self.test()  

        # return Response(status=200,content_type='application/json',
        #             body=json.dumps(  ))
        # return Response(status=200,content_type='application/json',
        #             body=json.dumps({'status':'success'}))
    def enable_version(self,req, **kwargs):
        # for i in range(1,9):
        #     os.system("sudo ovs-ofctl del-flows  s%d" %i )
        #     os.system("ovs-ofctl add-flow s%d priority=0,actions=CONTROLLER:65535" %i)
        #     print "del-flow in s%d" %i
        host_port_controller.host_port_controller_enable = False
        print "host_port_controller.host_port_controller_enable: ",host_port_controller.host_port_controller_enable
        multipath_controller.multipath_controller_enable = False
        print "multipath_controller.multipath_controller_enable: ",multipath_controller.multipath_controller_enable
        topo_controller.topo_controller_enable = False
        print "topo_controller.topo_controller_enable: ",topo_controller.topo_controller_enable
        version_controller.version_controller_enable = True
        print "version_controller.version_controller_enable: ",version_controller.version_controller_enable
        return Response(status=200,content_type='application/json',
                    body=json.dumps({'status':'success'}))