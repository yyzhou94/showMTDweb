# -*- coding: utf-8 -*-
"""
Author: gztsoul
Time: 2016/10/18 10:00


"""
mininet = True
if mininet:
    ipv4_dsts_net_addr = '10.0.0.'
    ipv4_dsts = {}
    for i in range(1,22):
        p=str(i)
        ip=ipv4_dsts_net_addr+p
        ipv4_dsts[ip]=0

    # gzt mark: switch_link_hosts 可以看成总的链路信息
    # switch_link_hosts = {dpid : {port:(MAC_ADDR, ip)} }
    IP_ADDR = ['10.0.0.'+'%d' %(i+1) for i in range(22)]
    MAC_ADDR = ['10:00:00:00:00:'+'%02d' %(i+1) for i in range(22)]
    switch_link_hosts = {1:{1:(MAC_ADDR[0],IP_ADDR[0])}, 7:{1:(MAC_ADDR[21],IP_ADDR[21])}}
    for i in range(4):
        switch_link_hosts.setdefault(i+2, {})
        for j in range(5):
            switch_link_hosts[i+2][j+1] = (MAC_ADDR[5*i + j + 1],IP_ADDR[5*i + j + 1])
else:
    ipv4_dsts = {'192.168.2.221':0, '192.168.2.221':0, '192.168.2.222':0, '192.168.2.223':0}


def _get_info(dpid, eth):
    in_port = 0
    MAC = None
    IP = None
    for port in switch_link_hosts[dpid]:
        if switch_link_hosts[dpid][port][0] == eth:
            in_port = port
            MAC = switch_link_hosts[dpid][port][0]
            IP = switch_link_hosts[dpid][port][1]
            break
    return (in_port, IP)

vul_impo_value = {0: (49, 36), 1: (58, 30), 2: (87, 72), 3: (55, 35),
                  4: (25, 66), 5: (52, 42), 6: (19, 77), 7: (59, 3),
                  8: (35, 71), 9: (34, 98), 10: (46, 87), 11: (22, 67),
                  12: (34, 38), 13: (81, 55), 14: (12, 62), 15: (86, 34),
                  16: (62, 39), 17: (74, 16), 18: (91, 66), 19: (52, 84),
                  20: (3, 17), 21: (62, 36)}
# topology infomation thi = [(dpid,mac_addr,vulu, impo)]
topology_hosts_info = []
topology_hosts_info.append((1,MAC_ADDR[0],vul_impo_value[0][0],vul_impo_value[0][1]))
for i in range(4):
    for j in range(5):
        topology_hosts_info.append((i+2, MAC_ADDR[5*i+j+1],
                                    vul_impo_value[5*i+j+1][0],
                                    vul_impo_value[5*i+j+1][1]))
topology_hosts_info.append((7,MAC_ADDR[21],vul_impo_value[21][0],vul_impo_value[21][1]))
