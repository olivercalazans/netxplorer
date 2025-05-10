# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import struct
import socket
from utils.network_info import get_my_ip_address
from utils.type_hints   import BPF_Instruction


class BPF_Filter:

    @staticmethod
    def get_filter(protocol:str) -> BPF_Instruction:
        match protocol:
            case 'TCP':      return BPF_Filter._get_tcp_parameters()
            case 'ICMP':     return BPF_Filter._get_icmp_parameters()
            case 'TCP-ICMP': return BPF_Filter._get_tcp_icmp_parameters()



    @staticmethod
    def _get_tcp_parameters() -> BPF_Instruction:
        my_ip_hex:int = struct.unpack('!I', socket.inet_aton(get_my_ip_address()))[0]
        return [
            (0x28, 0, 0, 0x0000000c),  # Load EtherType (offset 12)
            (0x15, 0, 5, 0x00000800),  # If != IPv4, jump to reject
            (0x20, 0, 0, 0x0000001e),  # Load IP dst address (offset 30)
            (0x15, 0, 3, my_ip_hex),   # If dst IP != My IP, jump to reject
            (0x30, 0, 0, 0x00000017),  # Load IP protocol (offset 23)
            (0x15, 0, 1, 0x00000006),  # If protocol != TCP, jump to reject
            (0x06, 0, 0, 0x00040000),  # Accept packet (capture 262144 bytes)
            (0x06, 0, 0, 0x00000000),  # Reject packet
        ]



    @staticmethod
    def _get_icmp_parameters() -> BPF_Instruction:
        my_ip_hex:int = struct.unpack('!I', socket.inet_aton(get_my_ip_address()))[0]
        return [
            (0x28, 0, 0, 0x0000000c),  # Load EtherType (offset 12)
            (0x15, 0,10, 0x00000800),  # If != IPv4, jump to reject
            (0x20, 0, 0, 0x0000001e),  # Load IP dst address (offset 30)
            (0x15, 0, 8, my_ip_hex),   # If dst IP != My, jump to reject
            (0x30, 0, 0, 0x00000017),  # Load IP protocol (offset 23)
            (0x15, 0, 6, 0x00000001),  # If protocol != ICMP (1), reject
            (0x28, 0, 0, 0x00000014),  # Load IP fragment offset field (offset 20)
            (0x45, 4, 0, 0x00001fff),  # If packet is a fragment, skip ICMP check
            (0xb1, 0, 0, 0x0000000e),  # Load frame offset (IP header length)
            (0x50, 0, 0, 0x0000000e),  # Load ICMP type (offset = IP header start + 0)
            (0x15, 0, 1, 0x00000000),  # If ICMP type != 0 (Echo Reply), reject
            (0x6,  0, 0, 0x00040000),  # Accept packet
            (0x6,  0, 0, 0x00000000),  # Reject packet
        ]
    


    @staticmethod
    def _get_tcp_icmp_parameters() -> BPF_Instruction:
        my_ip_hex:int = struct.unpack('!I', socket.inet_aton(get_my_ip_address()))[0]
        return [
            (0x28, 0, 0,  0x0000000c),  # Load EtherType (offset 12)
            (0x15, 0, 11, 0x00000800),  # If != IPv4, jump to reject
            (0x20, 0, 0,  0x0000001e),  # Load IP destination address (offset 30)
            (0x15, 0, 9,  my_ip_hex),   # If dst IP != My IP, jump to reject
            (0x30, 0, 0,  0x00000017),  # Load IP protocol (offset 23)
            (0x15, 6, 0,  0x00000006),  # If protocol != TCP, jump 6 instructions
            (0x15, 0, 6,  0x00000001),  # If protocol != ICMP (type 1 = Echo Request), jump 6 instructions
            (0x28, 0, 0,  0x00000014),  # Load IP fragment offset field (offset 20)
            (0x45, 4, 0,  0x00001fff),  # If packet is fragmented, skip ICMP check
            (0xb1, 0, 0,  0x0000000e),  # Load ICMP type (0 for Echo Reply)
            (0x50, 0, 0,  0x0000000e),  # Load the first byte of the ICMP header (type)
            (0x15, 0, 1,  0x00000000),  # If ICMP type != Echo Reply (0), reject
            (0x6,  0, 0,  0x00040000),  # Accept packet (capture 262144 bytes)
            (0x6,  0, 0,  0x00000000),  # Reject packet
        ]
