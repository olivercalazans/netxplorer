# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import os
from struct                  import Struct
from pkt_build.layer_4_utils import Layer_4_Utils


class ICMP:

    _ICMP_STRUCT:Struct     = Struct("!BBHHH")
    _BASE_ICMP_FIELDS:tuple = (
        8, #.......: ICMP type
        0, #.......: ICMP code
        0, #.......: Checksum (will be replaced)
        None, #....: ID (will be replaced)
        1 #........: Sequence Number
    )

    @classmethod
    def get_packet(cls) -> bytes:
            id:int        = os.getpid() & 0xFFFF
            fields:list   = list(cls._ICMP_STRUCT)
            fields[-2]    = id
            header:bytes  = cls._ICMP_STRUCT.pack(*fields)
            
            payload:bytes = os.urandom(56)
            checksum:int  = Layer_4_Utils.checksum(header + payload)
            
            fields[-3]    = checksum
            header:bytes  = cls._ICMP_STRUCT.pack(*fields)
            
            return header + payload