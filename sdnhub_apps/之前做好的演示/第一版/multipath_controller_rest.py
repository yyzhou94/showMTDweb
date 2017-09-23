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
# from multipath_controller import multipath_controller_enable



simple_switch_instance_name = 'multipath_controller'
# url = '/simpleswitch/multipath'

class MultipathRest(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
            ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'wsgi': WSGIApplication ,
        # 'dpset': dpset.DPSet,
        'multipath_controller':multipath_controller.Multipath
    }

    def __init__(self, *args, **kwargs):
        super(MultipathRest, self).__init__(*args, **kwargs)
        self.switches = {}
        wsgi = kwargs['wsgi']
        # dpset = kwargs['dpset']
        multipath_controller = kwargs['multipath_controller']
        self.waiters = {}
        self.data = {}
        # self.data['dpset'] = dpset
        self.data['waiters'] = self.waiters
        self.data['multipath_controller'] = multipath_controller



        wsgi.register(MultipathController, {simple_switch_instance_name : self})

        mapper = wsgi.mapper

        mapper.connect('multipath', '/v1.0/multipath/turnon',
                       controller=MultipathController, action='enable_multipath',
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

class MultipathController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(MultipathController, self).__init__(req, link, data, **config)
        self.multipath_controller = data[simple_switch_instance_name]
        # self.multipath_controller.multipath_controller_enable = False
        # self.dpset = data['dpset']

    # def start_test():
    #     from all_mininet import  test
    #     self.test()

        # return Response(status=200,content_type='application/json',
        #             body=json.dumps(  ))
        # return Response(status=200,content_type='application/json',
        #             body=json.dumps({'status':'success'}))

    def enable_multipath(self,req, **kwargs):
        for i in range(1,9):
            os.system("sudo ovs-ofctl del-flows  s%d" %i )
            os.system("ovs-ofctl add-flow s%d priority=0,actions=CONTROLLER:65535" %i)
            print "del-flow in s%d" %i
        host_port_controller.host_port_controller_enable = False
        print "host_port_controller.host_port_controller_enable: ",host_port_controller.host_port_controller_enable
        version_controller.version_controller_enable = False
        print  "version_controller.version_controller_enable: ",version_controller.version_controller_enable
        topo_controller.topo_controller_enable = False
        print "topo_controller.topo_controller_enable: ",topo_controller.topo_controller_enable
        multipath_controller.multipath_controller_enable = True
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
