#!/bin/sh

export PYTHONPATH=$PYTHONPATH:.

./bin/ryu-manager --observe-links ryu/app/sdnhub_apps/fileserver    ryu/app/sdnhub_apps/version_controller_rest    ryu/app/rest_topology   ryu/app/ofctl_rest  ryu/app/sdnhub_apps/topo_controller_rest
