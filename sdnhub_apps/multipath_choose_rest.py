import json
import logging

import os

from webob import Response
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

from ryu.lib.packet import ipv6


simple_switch_instance_name = 'multipath_choose'
url = '/simpleswitch/multipath'

class MultipathRest(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
            ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'wsgi': WSGIApplication ,
        # 'dpset': dpset.DPSet,
        'multipath_choose':multipath_choose_controller_group_table.MultipathChoose
    }

    def __init__(self, *args, **kwargs):
        super(MultipathRest, self).__init__(*args, **kwargs)
        
        wsgi = kwargs['wsgi']
        
        multipath_choose = kwargs['multipath_choose']
        self.waiters = {}
        self.data = {}
        
        self.data['waiters'] = self.waiters
        self.data['multipath_choose'] = multipath_choose



        wsgi.register(MultipathController, {simple_switch_instance_name : self})

        mapper = wsgi.mapper

        mapper.connect('multipath_choose', '/v1.0/choose/multipath',
                       controller=MultipathController, action='enable_multipath_choose',
                       conditions=dict(method=['POST']))
        mapper.connect('multipath_choose', '/v1.0/disable/multipath',
                       controller=MultipathController, action='disable_multipath_choose',
                       conditions=dict(method=['POST']))
        
    
class MultipathController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(MultipathController, self).__init__(req, link, data, **config)
        self.multipath_choose = data[simple_switch_instance_name]
        # self.dpset = data['dpset']

    def enable_multipath_choose(self,req, **kwargs):
        for i in range(1,9):
            os.system("sudo ovs-ofctl del-flows  s%d" %i )
        for i in range(1,9):
            os.system("ovs-ofctl add-flow s%d priority=0,actions=CONTROLLER:65535" %i)
        multipath_choose_controller_group_table.multipath_choose_enable = True
        print  "host_scan.host_scan_enable: ",host_discover.host_scan_enable
        print  "port_scan.port_scan_enable: ",port_scan.port_scan_enable
        print  "multipath_choose_controller_group_table.multipath_choose_enable: ",multipath_choose_controller_group_table.multipath_choose_enable
        print  "os_web_detect.os_web_detect_enable: ",os_web_detect.os_web_detect_enable
        print  "topo_disco_controller.topo_disco_enable: ",topo_disco_controller.topo_disco_enable
        # port_scan.port_scan_enable= False
        # host_discover.host_scan_enable = False
        # os_web_detect.os_web_detect_enable = False
        # topo_disco_controller.topo_disco_enable = False
        return Response(status=200,content_type='application/json',
                    body=json.dumps({'status':'success'}))

    def disable_multipath_choose(self,req, **kwargs):
        multipath_choose_controller_group_table.multipath_choose_enable = False
        print 'multipath_choose_controller_group_table.multipath_choose_enable',multipath_choose_controller_group_table.multipath_choose_enable
        return Response(status=200,content_type='application/json',
                    body=json.dumps({'status':'success'}))

