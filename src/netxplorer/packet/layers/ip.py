# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket
from random             import randint
from struct             import Struct
from utils.network_info import get_my_ip_address


class IP:

    # BUILDER ================================================================================================
    
    _IP_HEADER_STRUCT:Struct = Struct('!BBHHHBBH4s4s')
    _MY_IP:str               = socket.inet_aton(get_my_ip_address())
    _PROTOCOL_CODE:dict = {
        'TCP': socket.IPPROTO_TCP,
        'UDP': socket.IPPROTO_UDP
    }


    @classmethod
    def create_ip_header(cls, dst_ip:str, protocol:str) -> bytes:
        protocol_code:int = cls._PROTOCOL_CODE.get(protocol)
        return cls._IP_HEADER_STRUCT.pack(
            (4 << 4) + 5, #..............: IP version and IHL (Internet Header Length)
            0, #.........................: TOS (Type of Service)
            40, #........................: Total length
            randint(10000, 65535), #.....: IP ID
            0, #.........................: Flags and Fragment offset
            64, #........................: TLL (Time to Live)
            protocol_code, #.............: Protocol code
            0, #.........................: Checksum (Will be populated by the kernel)
            cls._MY_IP, #................: Source IP
            socket.inet_aton(dst_ip) #...: Destiny IP
        )
    


    # DISSECTOR ==============================================================================================

    _SOURCE_IP_STRUCT:Struct = Struct('4s')

    @staticmethod
    def get_ip_header(packet:memoryview, len_ether_header:int) -> memoryview:
        len_ip_header:int = (packet[len_ether_header] & 0x0F) * 4
        end:int           = len_ether_header + len_ip_header
        return packet[len_ether_header : end]



    @staticmethod
    def get_protocol(ip_header:memoryview) -> memoryview:
        return ip_header[9]



    @classmethod
    def get_source_ip(cls, ip_header:memoryview) -> str:
        raw_bytes:bytes = cls._SOURCE_IP_STRUCT.unpack(ip_header[12:16])[0]
        return socket.inet_ntoa(raw_bytes)
    


    @classmethod
    def get_destiny_ip(cls, ip_header:memoryview) -> str:
        raw_bytes:bytes = cls._SOURCE_IP_STRUCT.unpack(ip_header[16:20])[0]
        return socket.inet_ntoa(raw_bytes)