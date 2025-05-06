# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket
from struct                  import Struct
from pkt_build.layer_4_utils import Layer_4_Utils


class UDP:

    _UDP_STRUCT:Struct     = Struct('!HHHH')
    _UDP_BASE_FIELDS:tuple = (
        None, #...........: Source port
        None, #...........: Destiny port
        8, #..............: Payload
        0 #...............: Checksum
    )


    @classmethod
    def create_udp_header(cls, dst_ip:str, src_port:int, dst_port) -> bytes:
        fileds:list      = list(cls._UDP_BASE_FIELDS)
        fileds[0:2]      = [src_port, dst_port]
        udp_header:bytes = cls._UDP_STRUCT.pack(*fileds)
        
        pseudo_header:bytes = Layer_4_Utils.pseudo_header(dst_ip, socket.IPPROTO_UDP, len(udp_header))
        checksum:int        = Layer_4_Utils.checksum(pseudo_header + udp_header)
        
        fileds[-1]       = checksum
        udp_header:bytes = cls._UDP_STRUCT.pack(*fileds)
        
        return udp_header