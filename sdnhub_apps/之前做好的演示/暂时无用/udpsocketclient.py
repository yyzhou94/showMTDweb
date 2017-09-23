#!/usr/bin/env python
import socket
from bottle import run,template,route
addr=('127.0.0.1',10000)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
def test():
    @route("/test/")
    def trans():
        data = 'ceshi'
        s.sendto(data,addr)
    run(host = '10.109.247.234',port = 8005)

if __name__ == '__main__':
    test()
