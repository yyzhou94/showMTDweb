#!/usr/bin/python
# -*- coding: utf-8 -*-

from flask import Flask
import os
app = Flask(__name__)
@app.route('/change/')
def exp1():
    #os.system("kill $(ps -x | grep -m 1 ryu-manager | cut -d ' '  -f 1)")
    os.system("kill $(ps -x | grep -m 1 ryu-manager | awk '{print $1}')")
    # os.system('sudo ./ryu/app/sdnhub_apps/version.sh')



if __name__ == '__main__':
    app.run(host = '10.109.247.234',port = 8002)
