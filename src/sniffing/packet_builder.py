# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket
import struct
import random
import os
from net_info   import get_my_ip_address
from type_hints import Raw_Packet


# BUILDERS ===================================================================================================

def create_tcp_ip_packet(target_ip:str, dst_port:int, src_port:int) -> Raw_Packet:
    ip_header  = IP(target_ip)
    tcp_header = TCP(src_port, dst_port, target_ip)
    return Raw_Packet(ip_header + tcp_header)



# LAYERS =====================================================================================================

def ICMP() -> bytes:
    id     = os.getpid() & 0xFFFF
    header = struct.pack("!BBHHH",
                         8, #.......: ICMP type
                         0, #.......: ICMP code
                         0, #.......: Checksum
                         id, #......: ID
                         1 #........: Sequence Number
                         )
    payload = bytes((os.urandom(56)))
    chksum  = checksum(header + payload)
    header  = struct.pack("!BBHHH", 8, 0, chksum, id, 1)
    return header + payload



def IP(dst_ip:str) -> bytes:
    return struct.pack('!BBHHHBBH4s4s',
                       (4 << 4) + 5, #............................: IP version and IHL (Internet Header Length)
                       0, #.......................................: TOS (Type of Service)
                       40, #......................................: Total length
                       random.randint(10000, 65535), #............: IP ID
                       0, #.......................................: Flags and Fragment offset
                       64, #......................................: TLL (Time to Live)
                       socket.IPPROTO_TCP, #......................: Protocol
                       0, #.......................................: Checksum (Will be populated by the kernel)
                       socket.inet_aton(get_my_ip_address()), #...: Source IP
                       socket.inet_aton(dst_ip) #.................: Destiny IP
                       )



def TCP(src_port:str, dst_port:int, dst_ip:int) -> bytes:
    tcp_header = struct.pack('!HHLLBBHHH',
                             src_port, #.............: Source port
                             dst_port, #.............: Destiny port
                             0, #....................: Sequence
                             0, #....................: Acknowledge
                             (5 << 4), #.............: Data offset = 5 words (20 bytes), no options
                             (True << 1), #..........: Flags
                             socket.htons(5840), #...: Window size
                             0, #....................: Checksum (will be calculated)
                             0 #.....................: Urgent pointer
                             )
    pseudo_hdr   = pseudo_header(dst_ip, len(tcp_header))
    tcp_checksum = checksum(pseudo_hdr + tcp_header)
    return struct.pack('!HHLLBBHHH', src_port, dst_port, 0, 0, (5 << 4),
                       (True << 1), socket.htons(5840), tcp_checksum, 0)



def pseudo_header(dst_ip:str, tcp_length:int) -> bytes:
    return struct.pack('!4s4sBBH',
                       socket.inet_aton(get_my_ip_address()), #...: Source IP
                       socket.inet_aton(dst_ip), #................: Destiny IP
                       0, #.......................................: Reserved
                       socket.IPPROTO_TCP, #......................: Protocol
                       tcp_length #...............................: TCP header length
                       )



def checksum(data:bytes) -> int:
    if len(data) % 2:
        data += b"\x00"  # Padding

    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i+1]
    
    total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF