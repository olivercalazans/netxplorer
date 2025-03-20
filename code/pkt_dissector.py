# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import struct, socket
from type_hints import Raw_Packet


TCP_FLAG_MAP = {
        0b00010010: 'SYN-ACK', # (0b00000010 + 0b00010000)
        0b00000010: 'SYN',
        0b00010100: 'RST-ACK', # RST-ACK (0b00000100 + 0b00010000)
        0b00000100: 'RST',
        0b00000001: 'FIN'
    }


def dissect_tcp_packet(packet:Raw_Packet) -> dict|None:
    try:
        packet:Raw_Packet            = memoryview(packet)
        ip_header:tuple[int, bytes]  = struct.unpack('!BBHHHBBH4s4s', packet[14:34])
        tcp_header:tuple[int, bytes] = get_tcp_header(packet, ip_header)
        source_ip:str                = socket.inet_ntoa(ip_header[8])
        source_port:int              = tcp_header[0]
        tcp_flags:str                = TCP_FLAG_MAP.get(tcp_header[5] & (0b00111111), 'Filtered')
        return {'ip': source_ip, 'port': source_port, 'flags': tcp_flags}
    except (IndexError, struct.error, ValueError):
        return None


def get_tcp_header(packet:Raw_Packet, ip_header:tuple[int, bytes]) -> tuple[int, bytes]:
    ihl              = (ip_header[0] & 0x0F) * 4
    tcp_header_start = 14 + ihl
    tcp_header       = packet[tcp_header_start:tcp_header_start + 20]
    return  struct.unpack('!HHLLBBHHH', tcp_header)