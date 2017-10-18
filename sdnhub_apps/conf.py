#coding=utf-8
'''
Author: junjie
Time: 2017/10/11
'''
# 服务器第一个网口的地址
host = '10.109.16.212'

# 服务器另一个网口的地址
interface2 = '192.168.2.254'


# host_discover中的参数配置
host_fake = 50
host_drop_percent = 0.5
host_short_seq_len = 6


# port_scan中的参数配置
port_fake = 50
port_psa = 20
port_pa = 40
port_pr = 90

# os_detect中的参数配置
os_confusion_probability = 0.6
os_attacker = {'ip':'10.0.0.1', 'mac':'10:00:00:00:00:01', 'port': 1}
os_victim = {'ip':'10.0.0.2', 'mac':'10:00:00:00:00:02', 'port': 4}
os_fake_host = {'ip': '192.168.2.220', 'mac': '00:00:00:22:00:01', 'port': 5}

# topo_discover中的参数配置
# 隐藏主机的百分比
topo_hosts_hide_percent = 0.5
# 合并的交换机的百分比
topo_switches_merge_percent = 0.5


