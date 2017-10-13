#!/bin/sh

export PYTHONPATH=$PYTHONPATH:.

./bin/ryu-manager --observe-links   ryu.app.sdnhub_apps.fileserver ryu.app.sdnhub_apps.multipath_choose_rest ryu.app.rest_topology  ryu.topology.switches    ryu.app.ofctl_rest  
