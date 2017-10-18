#!/bin/sh

export PYTHONPATH=$PYTHONPATH:.

./bin/ryu-manager --observe-links    ryu.app.sdnhub_apps.host_discover_rest
