import json
import logging

import os

from webob import Response
from ryu.base import app_manager

from ryu.app.sdnhub_apps import host_discover_with_snort
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




simple_switch_instance_name = 'host_discover_with_snort'


class HostSnortRest(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
            ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'wsgi': WSGIApplication ,
        # 'dpset': dpset.DPSet,
        'host_discover_with_snort':host_discover_with_snort.SimpleMonitor,
        'snortlib': snortlib.SnortLib
    }

    def __init__(self, *args, **kwargs):
        super(HostSnortRest, self).__init__(*args, **kwargs)
        self.switches = {}
        wsgi = kwargs['wsgi']
        self.snort = kwargs['snortlib']
        socket_config = {'unixsock': True}

        self.snort.set_config(socket_config)
        self.snort.start_socket_server()
        dpset = kwargs['dpset']
        host_discover_with_snort = kwargs['host_discover_with_snort']
        self.waiters = {}
        self.data = {}
        # self.data['dpset'] = dpset
        self.data['waiters'] = self.waiters
        self.data['host_discover_with_snort'] = host_discover_with_snort



        wsgi.register(HostSnortController, {simple_switch_instance_name : self})

        mapper = wsgi.mapper

        mapper.connect('host_discover_with_snort', '/v1.0/scan/turnon',
                       controller=HostSnortController, action='enable_scan',
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

class HostSnortController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(HostSnortController, self).__init__(req, link, data, **config)
        self.host_discover_with_snort = data[simple_switch_instance_name]
        # self.multipath_controller.multipath_controller_enable = False
        # self.dpset = data['dpset']

    # def start_test():
    #     from all_mininet import  test
    #     self.test()

        # return Response(status=200,content_type='application/json',
        #             body=json.dumps(  ))
        # return Response(status=200,content_type='application/json',
        #             body=json.dumps({'status':'success'}))

    def enable_scan(self,req, **kwargs):
        for i in range(1,9):
            os.system("sudo ovs-ofctl del-flows  s%d" %i )
            os.system("ovs-ofctl add-flow s%d priority=0,actions=CONTROLLER:65535" %i)
            print "del-flow in s%d" %i
        host_discover_with_snort.START_MTD = True
        print "host_discover_with_snort.START_MTD: ",host_discover_with_snort.START_MTD
        version_controller.version_controller_enable = False
        print  "version_controller.version_controller_enable: ",version_controller.version_controller_enable
        topo_controller.topo_controller_enable = False
        print "topo_controller.topo_controller_enable: ",topo_controller.topo_controller_enable
        multipath_controller.multipath_controller_enable = False
        print "multipath_controller.multipath_controller_enable: ",multipath_controller.multipath_controller_enable
        return Response(status=200,content_type='application/json',
                    body=json.dumps({'status':'success'}))


    # @route('simpleswitch', url, methods=['GET'], requirements={'dpid': dpid_lib.DPID_PATTERN})
    # def list_mac_table(self, req, **kwargs):
    #
    #     simple_switch = self.simpl_switch_spp
    #     dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
    #
    #     if dpid not in simple_switch.mac_to_port:
    #         return Response(status=404)
    #
    #     mac_table = simple_switch.mac_to_port.get(dpid, {})
    #     body = json.dumps(mac_table)
    #     return Response(content_type='application/json', body=body)
    #
    # @route('simpleswitch', url, methods=['PUT'], requirements={'dpid': dpid_lib.DPID_PATTERN})
    # def put_mac_table(self, req, **kwargs):
    #
    #     simple_switch = self.simpl_switch_spp
    #     dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
    #     new_entry = eval(req.body)
    #
    #     if dpid not in simple_switch.mac_to_port:
    #         return Response(status=404)
    #
    #     try:
    #         mac_table = simple_switch.set_mac_to_port(dpid, new_entry)
    #         body = json.dumps(mac_table)
    #         return Response(content_type='application/json', body=body)
    #     except Exception as e:
    #         return Response(status=500)
