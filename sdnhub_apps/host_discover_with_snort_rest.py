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


class HostSnortController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(HostSnortController, self).__init__(req, link, data, **config)
        self.host_discover_with_snort = data[simple_switch_instance_name]
        # self.multipath_controller.multipath_controller_enable = False
        # self.dpset = data['dpset']

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

