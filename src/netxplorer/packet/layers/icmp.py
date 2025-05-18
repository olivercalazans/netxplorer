# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import os
from struct                      import Struct
from packet.layers.layer_4_utils import Layer_4_Utils


class ICMP:

    _ICMP_HEADER_STRUCT:Struct = Struct("!BBHHH")
    
    # BUILDER ================================================================================================

    _BASE_ICMP_FIELDS:tuple    = (
        8, #.......: ICMP type
        0, #.......: ICMP code
        0, #.......: Checksum (will be replaced)
        None, #....: ID (will be replaced)
        1 #........: Sequence Number
    )


    @classmethod
    def create_icmp_header(cls) -> bytes:
            id:int        = os.getpid() & 0xFFFF
            fields:list   = list(cls._BASE_ICMP_FIELDS)
            fields[-2]    = id
            header:bytes  = cls._ICMP_HEADER_STRUCT.pack(*fields)
            
            payload:bytes = os.urandom(56)
            checksum:int  = Layer_4_Utils.checksum(header + payload)
            
            fields[-3]    = checksum
            header:bytes  = cls._ICMP_HEADER_STRUCT.pack(*fields)
            
            return header + payload



    # DISSECTOR ==============================================================================================

    @classmethod
    def get_icmp_header(cls, packet:memoryview, len_ip_header:int) -> memoryview:
        len_ether_header:int = 14
        start:int            = len_ether_header + len_ip_header
        end:int              = start + 8
        return cls._ICMP_HEADER_STRUCT.unpack(packet[start : end])



    @staticmethod
    def get_icmp_type_and_code(icmp_header:memoryview) -> tuple[int, int]:
        icmp_type:int = icmp_header[0]
        icmp_code:int = icmp_header[1]
        return icmp_type, icmp_code



    @staticmethod
    def extract_icmp_payload(packet:memoryview, len_ip_header:int) -> bytes:
        try:
            icmp_header:int   = 8
            payload_start:int = len_ip_header + icmp_header
            return packet[payload_start : ]
        except:
            return None