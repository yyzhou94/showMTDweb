import json
import logging

import os

from webob import Response
from ryu.base import app_manager

from ryu.app.sdnhub_apps import host_discover
from ryu.app.sdnhub_apps import port_scan
from ryu.app.sdnhub_apps import os_web_detect
from ryu.app.sdnhub_apps import multipath_choose_controller_group_table
from ryu.app.sdnhub_apps import topo_disco_controller
from ryu.app.sdnhub_apps import multipath_choose_controller


from webob import Response
from ryu.lib import snortlib
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




simple_switch_instance_name = 'os_web_detect'


class OsSnortRest(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
            ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'wsgi': WSGIApplication ,
        # 'dpset': dpset.DPSet,
        'os_web_detect':os_web_detect.OSWebVersionDetect
        # 'snortlib': snortlib.SnortLib
    }

    def __init__(self, *args, **kwargs):
        super(OsSnortRest, self).__init__(*args, **kwargs)
        self.switches = {}
        wsgi = kwargs['wsgi']
        # self.snort = kwargs['snortlib']
        # socket_config = {'unixsock': True}

        # self.snort.set_config(socket_config)
        # self.snort.start_socket_server()
        # dpset = kwargs['dpset']
        os_web_detect = kwargs['os_web_detect']
        self.waiters = {}
        self.data = {}
        # self.data['dpset'] = dpset
        self.data['waiters'] = self.waiters
        self.data['os_web_detect'] = os_web_detect



        wsgi.register(OsSnortController, {simple_switch_instance_name : self})

        mapper = wsgi.mapper

        mapper.connect('os_scan', '/v1.0/version/turnon',
                       controller=OsSnortController, action='enable_os_detect',
                       conditions=dict(method=['POST']))

        # mapper.connect('multipath_controller', '/simpleswitch/multipath',
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

class OsSnortController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(OsSnortController, self).__init__(req, link, data, **config)
        self.os_web_detect = data[simple_switch_instance_name]
        # self.multipath_controller.multipath_controller_enable = False
        # self.dpset = data['dpset']

    def enable_os_detect(self,req, **kwargs):
        for i in range(1,9):
            os.system("sudo ovs-ofctl del-flows  s%d" %i )
        for i in range(1,8):    
            os.system("ovs-ofctl add-flow s%d priority=0,actions=CONTROLLER:65535" %i)
        os_web_detect.os_web_detect_enable = True
        print "os_web_detect.os_web_detect_enable: ",os_web_detect.os_web_detect_enable
        port_scan.port_scan_enable = False
        host_discover.host_scan_enable = False
        multipath_choose_controller_group_table.multipath_choose_enable = False
        # multipath_choose_controller.multipath_choose_enable = False
        topo_disco_controller.topo_disco_enable = False
        return Response(status=200,content_type='application/json',
                    body=json.dumps({'status':'success'}))

