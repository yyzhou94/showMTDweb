# -*- coding: utf-8 -*-

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
import struct
import time

def lltd_parse(msg):
    pkt = packet.Packet(msg.data)
    eth = pkt.get_protocols(ethernet.ethernet)[0]
    dst = eth.dst
    src = eth.src

    # 解析LLTD报文
    data = msg.data
    l = len(data)
    fmt = '!6s6s2sssss6s6s2s'
    fmt = fmt + str(l-struct.calcsize(fmt)) + 's'
    # fmt = [6eth_dst, 6eth_src, 2eth_type, lltd_version, lltd_service,
    #        lltd_reserved, lltd_function, 6lltd_real_eth_dst, 6lltd_real_eth_src, 2lltd_seqNum,
    #       (2lltd_recveeDescsNum, lltd_recveeDescsItem)]
    fmt_data = list(struct.unpack(fmt, data))

    # 解析type of service
    lltd_service_code = fmt_data[4]
    if lltd_service_code == '\x00':
        lltd_service = 'Topology Discovery'
    elif lltd_service_code == '\x01':
        lltd_service = 'Quick Discovery'
    elif lltd_service_code == '\x02':
        lltd_service = 'QoS Diagnostics'
    else:
        lltd_service = 'Unknown'

    # 解析function
    isEmit = False
    isQueryResp = False
    lltd_function_code = fmt_data[6]
    if lltd_service_code == '\x00':
        if lltd_function_code == '\x00':
            lltd_function = 'Discover'
        elif lltd_function_code == '\x01':
            lltd_function = 'Hello'
        elif lltd_function_code == '\x02':
            lltd_function = 'Emit'
            # 解析Emit报文
            # 首先解析出 emit_items_num
            isEmit = True
            emit_data = fmt_data[-1]
            fmt_emit = '!h'
            fmt_emit = fmt_emit + str(len(emit_data)-struct.calcsize(fmt_emit)) + 's'
            fmt_emit_data = list(struct.unpack(fmt_emit, emit_data))
            emit_items_num = fmt_emit_data[0]

            # 然后解析出emit_items
            emit_items = [ {} for i in range(emit_items_num) ]
            emit_item_data = fmt_emit_data[1]
            fmt_emit_item = '!'
            for i in range(emit_items_num):
                fmt_emit_item += 'ss6s6s'
            fmt_emit_item = fmt_emit_item + str(len(emit_item_data)-struct.calcsize(fmt_emit_item)) + 's'
            emit_items_data = list(struct.unpack(fmt_emit_item, emit_item_data))
            for i in range(emit_items_num):
                tmp = emit_items_data[4*i : 4*i+4]
                # 解析emit_item里具体内容
                if tmp[0] == '\x00':
                    emit_items[i]['emit_item_type'] = 'Train'
                elif tmp[0] == '\x01':
                    emit_items[i]['emit_item_type'] = 'Probe'
                else:
                    emit_items[i]['emit_item_type'] = 'Unknown'
                emit_items[i]['emit_item_src'] = stringToMac(tmp[2])
                emit_items[i]['emit_item_dst'] = stringToMac(tmp[3])
        elif lltd_function_code == '\x03':
            lltd_function = 'Train'
        elif lltd_function_code == '\x04':
            lltd_function = 'Probe'
        elif lltd_function_code == '\x05':
            lltd_function = 'Ack'
        elif lltd_function_code == '\x06':
            lltd_function = 'Query'
        elif lltd_function_code == '\x07':
            lltd_function = 'QueryResp'
            # 解析QueryResp报文
            # 首先解析出 queryResp_items_num
            isQueryResp = True
            queryResp_data = fmt_data[-1]
            fmt_queryResp = '!h'
            fmt_queryResp = fmt_queryResp + str(len(queryResp_data)-struct.calcsize(fmt_queryResp)) + 's'
            fmt_queryResp_data = list(struct.unpack(fmt_queryResp, queryResp_data))
            queryResp_items_num = fmt_queryResp_data[0]

            # 然后解析出 queryResp_items
            queryResp_items = [ {} for i in range(queryResp_items_num) ]
            queryResp_item_data = fmt_queryResp_data[1]
            fmt_queryResp_item = '!'
            for i in range(queryResp_items_num):
                fmt_queryResp_item += 'H6s6s6s'
            fmt_queryResp_item = fmt_queryResp_item + str(len(queryResp_item_data)-struct.calcsize(fmt_queryResp_item)) + 's'
            queryResp_items_data = list(struct.unpack(fmt_queryResp_item, queryResp_item_data))
            for i in range(queryResp_items_num):
                tmp = queryResp_items_data[4*i : 4*i+4]
                # 解析queryResp_item里具体内容
                if tmp[0] == 0:
                    queryResp_items[i]['queryResp_item_type'] = 'Probe'
                elif tmp[0] == 1:
                    queryResp_items[i]['queryResp_item_type'] = 'ARP'
                else:
                    queryResp_items[i]['queryResp_item_type'] = 'Unknown'
                queryResp_items[i]['queryResp_item_real_src'] = stringToMac(tmp[1])
                queryResp_items[i]['queryResp_item_src'] = stringToMac(tmp[2])
                queryResp_items[i]['queryResp_item_dst'] = stringToMac(tmp[3])
        elif lltd_function_code == '\x08':
            lltd_function = 'Reset'
        elif lltd_function_code == '\x09':
            lltd_function = 'Charge'
        elif lltd_function_code == '\x0A':
            lltd_function = 'Flat'
        elif lltd_function_code == '\x0B':
            lltd_function = 'QueryLargeTlv'
        elif lltd_function_code == '\x0C':
            lltd_function = 'QueryLargeTlvResp'
        else:
            lltd_function = 'Unknown'
    else:
        lltd_function = 'Unknown'

    # print 'LLTD | Service: %18s | Function: %s | From: %s | To: %s' % (lltd_service, lltd_function, src, dst),
    print 'LLTD | %-9s | From: %s | To : %s' % (lltd_function, src, dst),
    # print 'LLTD | %.4f | %-9s | From: %s | To : %s' % (time.time()%10000, lltd_function, src, dst),

    if isEmit:
        print '| Number: %d' % emit_items_num,
        for i in range(emit_items_num):
            emit_item = emit_items[i]
            print '\n     | %-9s | Src : %s | Dst: %s' % (emit_item['emit_item_type'], emit_item['emit_item_src'], emit_item['emit_item_dst']),
            # print '\n                 | %-9s | Src : %s | Dst: %s' % (emit_item['emit_item_type'], emit_item['emit_item_src'], emit_item['emit_item_dst']),
    if isQueryResp:
        print '| Number: %d' % queryResp_items_num,
        for i in range(queryResp_items_num):
            queryResp_item = queryResp_items[i]
            print '\n     | %-9s | Src : %s | Dst: %s | Real Src: %s' % (queryResp_item['queryResp_item_type'], queryResp_item['queryResp_item_src'], queryResp_item['queryResp_item_dst'], queryResp_item['queryResp_item_real_src']),
            # print '\n                 | %-9s | Src : %s | Dst: %s | Real Src: %s' % (queryResp_item['queryResp_item_type'], queryResp_item['queryResp_item_src'], queryResp_item['queryResp_item_dst'], queryResp_item['queryResp_item_real_src']),
    print '\n',


    # if fmt_data[6] == '\x07':
    #     print 'QueryResp'
    #     print fmt_data[10]
    #     fmt_data[10] = '\x00' * len(fmt_data[10])
    #     new_data = struct.pack(fmt, *fmt_data)
    #     actions = []
    #
    #     out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=new_data)
    #     datapath.send_msg(out)
    #     return

def stringToMac(s):
    tmp = struct.unpack('!BBBBBB', s)
    return ':'.join(map(lambda x: '0'+x if len(x)==1 else x, map(lambda x: hex(x)[2:], tmp)))
