# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket
from struct                      import Struct 
from packet.layers.layer_4_utils import Layer_4_Utils
from utils.port_set              import Port_Set


class UDP:

    _UDP_HEADER_STRUCT:Struct    = Struct('!HHHH')

    # BUILDE =================================================================================================

    _UDP_BASE_FIELDS:tuple = (
        None, #...........: Source port
        None, #...........: Destiny port
        8, #..............: Payload
        0 #...............: Checksum
    )


    @classmethod
    def create_udp_header(cls, dst_ip:str, dst_port) -> bytes:
        src_port:int     = Port_Set.get_random_port()

        fileds:list      = list(cls._UDP_BASE_FIELDS)
        fileds[0:2]      = [src_port, dst_port]
        udp_header:bytes = cls._UDP_HEADER_STRUCT.pack(*fileds)
        
        pseudo_header:bytes = Layer_4_Utils.pseudo_header(dst_ip, socket.IPPROTO_UDP, len(udp_header))
        checksum:int        = Layer_4_Utils.checksum(pseudo_header + udp_header)
        
        fileds[-1]       = checksum
        udp_header:bytes = cls._UDP_HEADER_STRUCT.pack(*fileds)
        
        return udp_header
    


    # DISSECTOR ==============================================================================================

    @classmethod
    def get_udp_header(cls, packet:memoryview, len_ip_header:int) -> memoryview:
        len_ether_header:int = 14
        udp_offset:int       = len_ether_header + len_ip_header
        return cls._UDP_HEADER_STRUCT.unpack(packet[udp_offset:udp_offset + 8])
    
    
    
    @staticmethod
    def get_udp_destiny_port(udp_header:memoryview) -> memoryview:
        return udp_header[1]