# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import struct, socket
from type_hints import Raw_Packet


# TCP PACKET DISSECTOR ==============================================================================
IP_HEADER_STRUCT  = struct.Struct('!BBHHHBBH4s4s')
TCP_HEADER_STRUCT = struct.Struct('!HHLLBBHHH')
TCP_FLAG_MAP      = {
        0b00010010: 'SYN-ACK', # (0b00000010 + 0b00010000)
        0b00000010: 'SYN',
        0b00010100: 'RST-ACK', # RST-ACK (0b00000100 + 0b00010000)
        0b00000100: 'RST',
        0b00000001: 'FIN'
    }


def dissect_tcp_packet(packet:Raw_Packet) -> tuple[int, str]:
    try:
        packet:Raw_Packet            = memoryview(packet)
        ip_header:tuple[int, bytes]  = IP_HEADER_STRUCT.unpack(packet[14:34])
        ihl:int                      = (ip_header[0] & 0x0F) * 4
        header_start:int             = 14 + ihl
        header_end:int               = header_start + 20
        tcp_header:tuple[int, bytes] = TCP_HEADER_STRUCT.unpack(packet[header_start:header_end])
        source_port:int              = tcp_header[0]
        tcp_flags:str                = TCP_FLAG_MAP.get(tcp_header[5] & (0b00111111), 'Filtered')
        
        return (source_port, tcp_flags)
    except (IndexError, struct.error, ValueError):
        return None



# ICMP PACKET DISSECTOR ============================================================================

def dissect_icmp_packet(packet:Raw_Packet) -> str:
    packet:Raw_Packet    = memoryview(packet)
    ip_header:memoryview = packet[14:34]
    src_ip:bytes         = struct.unpack('!4s', ip_header[12:16])[0]
    src_ip:str           = socket.inet_ntoa(src_ip)
    return src_ip
