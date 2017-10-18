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


simple_switch_instance_name = 'host_discover'
# url = '/simpleswitch/hostport'

class HostRest(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
            ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'wsgi': WSGIApplication ,
        # 'dpset': dpset.DPSet,
        'host_discover':host_discover.SimpleMonitor
    }

    def __init__(self, *args, **kwargs):
        super(HostRest, self).__init__(*args, **kwargs)

        wsgi = kwargs['wsgi']

        host_discover = kwargs['host_discover']
        self.waiters = {}
        self.data = {}

        self.data['waiters'] = self.waiters
        self.data['host_discover'] = host_discover



        wsgi.register(HostController, {simple_switch_instance_name : self})

        mapper = wsgi.mapper

        mapper.connect('host_scan', '/v1.0/scan/host',
                       controller=HostController, action='enable_host_scan',
                       conditions=dict(method=['POST']))
        mapper.connect('host_scan','/v1.0/disable/host',
                       controller=HostController, action='disable_host_scan',
                       conditions=dict(method=['POST']))
        mapper.connect('host_scan_mtd','/v1.0/scan/host_mtd',
                       controller=HostController, action='host_mtd',
                       conditions=dict(method=['POST']))
        mapper.connect('host_scan_mtd','/v1.0/scan/stop_host_mtd',
                       controller=HostController, action='stop_host_mtd',
                       conditions=dict(method=['POST']))
        mapper.connect('reset','/v1.0/reset',
                       controller=HostController, action='reset',
                       conditions=dict(method=['POST']))


class HostController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(HostController, self).__init__(req, link, data, **config)
        self.host_discover = data[simple_switch_instance_name]
        # self.dpset = data['dpset']

    def host_mtd(self,req, **kwargs):
        host_discover.START_MTD = True
        return Response(status=200,content_type='application/json',
                    body=json.dumps({'status':'success'}))
    def stop_host_mtd(self,req, **kwargs):
        host_discover.START_MTD = False
        return Response(status=200,content_type='application/json',
                    body=json.dumps({'status':'success'}))


    def reset(self,req, **kwargs):
        host_discover.host_scan_enable = False
        port_scan.port_scan_enable = False
        multipath_choose_controller_group_table.multipath_choose_enable = False
        os_web_detect.os_web_detect_enable = False
        topo_disco_controller.topo_disco_enable = False
        host_discover.START_MTD = False
        port_scan.START_MTD = False
        topo_disco_controller.START_MTD = False
        self.del_flow()


        return Response(status=200,content_type='application/json',
                    body=json.dumps({'status':'success'}))

    def enable_host_scan(self,req, **kwargs):
        for i in range(1,9):
            os.system("sudo ovs-ofctl del-flows  s%d" %i )
            # os.system("ovs-ofctl add-flow s%d priority=0,actions=CONTROLLER:65535" %i)
            # print "del-flow in s%d" %i
        for i in range(1,8):
            os.system("ovs-ofctl add-flow s%d priority=0,actions=CONTROLLER:65535" %i)


        host_discover.host_scan_enable = True

        print  "host_scan.host_scan_enable: ",host_discover.host_scan_enable
        print  "port_scan.port_scan_enable: ",port_scan.port_scan_enable
        print  "multipath_choose_controller_group_table.multipath_choose_enable: ",multipath_choose_controller_group_table.multipath_choose_enable
        print  "os_web_detect.os_web_detect_enable: ",os_web_detect.os_web_detect_enable
        print  "topo_disco_controller.topo_disco_enable: ",topo_disco_controller.topo_disco_enable
        # port_scan.port_scan_enable = False
        # multipath_choose_controller_group_table.multipath_choose_enable = False
        # os_web_detect.os_web_detect_enable = False
        # topo_disco_controller.topo_disco_enable = False
        return Response(status=200,content_type='application/json',
                    body=json.dumps({'status':'success'}))
    def disable_host_scan(self,req, **kwargs):

        host_discover.host_scan_enable = False

        print  "host_discover.host_scan_enable: ",host_discover.host_scan_enable
        # port_scan.port_scan_enable = False
        # multipath_choose_controller_group_table.multipath_choose_enable = False
        # os_web_detect.os_web_detect_enable = False
        # topo_disco_controller.topo_disco_enable = False
        return Response(status=200,content_type='application/json',
                    body=json.dumps({'status':'success'}))

    def del_flow(self):
        for i in range(1,9):
            os.system("sudo ovs-ofctl del-flows  s%d" %i )