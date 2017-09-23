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
        mapper.connect('topo_disco', '/v1.0/disco/topo_mtd',
                       controller=TopoController, action='topo_mtd',
                       conditions=dict(method=['POST']))
        mapper.connect('topo_disco', '/v1.0/disco/stop_topo_mtd',
                       controller=TopoController, action='stop_topo_mtd',
                       conditions=dict(method=['POST']))
        mapper.connect('topo_disco', '/v1.0/disable/topo',
                       controller=TopoController, action='disable_topo_disco',
                       conditions=dict(method=['POST']))
        
   
class TopoController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(TopoController, self).__init__(req, link, data, **config)
        self.topo_disco = data[simple_switch_instance_name]
        # self.dpset = data['dpset']

    def topo_mtd(self,req, **kwargs):
        topo_disco_controller.START_MTD = True
        return Response(status=200,content_type='application/json',
                    body=json.dumps({'status':'success'}))
    def stop_topo_mtd(self,req, **kwargs):
        for i in range(1,9):
            os.system("sudo ovs-ofctl del-flows  s%d" %i )
        for i in range(1,8):
            os.system("ovs-ofctl add-flow s%d priority=1,actions=CONTROLLER:65535" %i)
        topo_disco_controller.START_MTD = False
        print 'topo_disco_controller.START_MTD',topo_disco_controller.START_MTD
        return Response(status=200,content_type='application/json',
                    body=json.dumps({'status':'success'}))



    def enable_topo_disco(self,req, **kwargs):
        for i in range(1,9):
            os.system("sudo ovs-ofctl del-flows  s%d" %i )
        for i in range(1,8):
            os.system("ovs-ofctl add-flow s%d priority=1,actions=CONTROLLER:65535" %i)
    
        topo_disco_controller.topo_disco_enable = True
        print  "host_scan.host_scan_enable: ",host_discover.host_scan_enable
        print  "port_scan.port_scan_enable: ",port_scan.port_scan_enable
        print  "multipath_choose_controller_group_table.multipath_choose_enable: ",multipath_choose_controller_group_table.multipath_choose_enable
        print  "os_web_detect.os_web_detect_enable: ",os_web_detect.os_web_detect_enable
        print  "topo_disco_controller.topo_disco_enable: ",topo_disco_controller.topo_disco_enable
        return Response(status=200,content_type='application/json',
                    body=json.dumps({'status':'success'}))

    def disable_topo_disco(self,req, **kwargs):
        topo_disco_controller.topo_disco_enable = False
        print "topo_disco_controller.topo_disco_enable = %s "  %topo_disco_controller.topo_disco_enable
        return Response(status=200,content_type='application/json',
                    body=json.dumps({'status':'success'}))
