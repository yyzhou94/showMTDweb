#!/bin/sh

export PYTHONPATH=$PYTHONPATH:.

./bin/ryu-manager --observe-links ryu.app.sdnhub_apps.fileserver ryu.app.sdnhub_apps.host_discover_rest ryu.app.sdnhub_apps.topo_disco_rest  ryu.app.sdnhub_apps.port_scan_rest ryu.app.sdnhub_apps.os_web_detect_rest ryu.app.sdnhub_apps.multipath_choose_rest  ryu.app.rest_topology   ryu.app.ofctl_rest  ryu.topology.switches

