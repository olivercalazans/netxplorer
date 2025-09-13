# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket
from struct             import Struct
from utils.network_info import get_my_ip_address


class Layer_4_Utils:

    _PSEUDO_HEADER_STRUCT:Struct = Struct('!4s4sBBH')
    _MY_IP:str = socket.inet_aton(get_my_ip_address())


    @classmethod
    def pseudo_header(cls, dst_ip:str, protocol:int, length:int) -> bytes:
        return cls._PSEUDO_HEADER_STRUCT.pack(
                           cls._MY_IP, #.................: Source IP
                           socket.inet_aton(dst_ip), #...: Destiny IP
                           0, #..........................: Reserved
                           protocol, #...................: Protocol
                           length #......................: TCP or UDP header length
                )


    @staticmethod
    def checksum(data:bytes) -> int:
        if len(data) % 2:
            data += b"\x00"  # Padding

        total:int = 0
        for i in range(0, len(data), 2):
            total += (data[i] << 8) + data[i+1]

        total:int = (total & 0xFFFF) + (total >> 16)
        return ~total & 0xFFFF