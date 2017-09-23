import json
import logging

import os

from webob import Response
from ryu.base import app_manager

from ryu.app.sdnhub_apps import host_discover
from ryu.app.sdnhub_apps import port_scan
from ryu.app.sdnhub_apps import os_web_detect_snort
from ryu.app.sdnhub_apps import multipath_choose_controller_group_table
from ryu.app.sdnhub_apps import topo_disco_controller



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
        'os_web_detect_snort':os_web_detect_snort.OSWebVersionDetect,
        'snortlib': snortlib.SnortLib
    }

    def __init__(self, *args, **kwargs):
        super(OsSnortRest, self).__init__(*args, **kwargs)
        self.switches = {}
        wsgi = kwargs['wsgi']
        socket_config = {'unixsock': True}
        self.snort = kwargs['snortlib']
        self.snort.set_config(socket_config)
        self.snort.start_socket_server()
        # self.snort = kwargs['snortlib']
        # socket_config = {'unixsock': True}

        # self.snort.set_config(socket_config)
        # self.snort.start_socket_server()
        # dpset = kwargs['dpset']
        os_web_detect_snort = kwargs['os_web_detect_snort']
        self.waiters = {}
        self.data = {}
        # self.data['dpset'] = dpset
        self.data['waiters'] = self.waiters
        self.data['os_web_detect_snort'] = os_web_detect_snort



        wsgi.register(OsSnortController, {simple_switch_instance_name : self})

        mapper = wsgi.mapper

        mapper.connect('os_scan', '/v1.0/version/turnon',
                       controller=OsSnortController, action='enable_os_detect',
                       conditions=dict(method=['POST']))

        mapper.connect('os_scan', '/v1.0/disable/version',
                       controller=OsSnortController, action='disable_os_detect',
                       conditions=dict(method=['POST']))

    
class OsSnortController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(OsSnortController, self).__init__(req, link, data, **config)
        self.os_web_detect_snort = data[simple_switch_instance_name]
        # self.multipath_controller.multipath_controller_enable = False
        # self.dpset = data['dpset']

    def enable_os_detect(self,req, **kwargs):
        for i in range(1,9):
            os.system("sudo ovs-ofctl del-flows  s%d" %i )
        for i in range(1,8):    
            os.system("ovs-ofctl add-flow s%d priority=0,actions=CONTROLLER:65535" %i)
        os_web_detect_snort.os_web_detect_enable = True
           
        print  "host_scan.host_scan_enable: ",host_discover.host_scan_enable
        print  "port_scan.port_scan_enable: ",port_scan.port_scan_enable
        print  "multipath_choose_controller_group_table.multipath_choose_enable: ",multipath_choose_controller_group_table.multipath_choose_enable
        print  "os_web_detect.os_web_detect_enable: ",os_web_detect_snort.os_web_detect_enable
        print  "topo_disco_controller.topo_disco_enable: ",topo_disco_controller.topo_disco_enable
        # port_scan.port_scan_enable = False
        # host_discover.host_scan_enable = False
        # multipath_choose_controller_group_table.multipath_choose_enable = False
        # multipath_choose_controller.multipath_choose_enable = False
        # topo_disco_controller.topo_disco_enable = False
        return Response(status=200,content_type='application/json',
                    body=json.dumps({'status':'success'}))


    def disable_os_detect(self,req, **kwargs):
        os_web_detect_snort.os_web_detect_enable = False
        print "os_web_detect.os_web_detect_enable: ",os_web_detect_snort.os_web_detect_enable
        return Response(status=200,content_type='application/json',
                    body=json.dumps({'status':'success'}))


