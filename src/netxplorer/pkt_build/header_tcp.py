# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket
from struct                  import Struct
from pkt_build.layer_4_utils import Layer_4_Utils


class TCP:

    _TCP_STRUCT: Struct     = Struct('!HHLLBBHHH')
    _BASE_TCP_FIELDS: tuple = (
        None, #.................: Source port (will be replaced)
        None, #.................: Destiny port (will be replaced)
        0, #....................: Sequence
        0, #....................: Acknowledge
        (5 << 4), #.............: Data offset = 5 words (20 bytes), no options
        (True << 1), #..........: Flags
        socket.htons(5840), #...: Window size
        0, #....................: Checksum (will be calculated)
        0 #.....................: Urgent pointer
    )


    @classmethod
    def create_tcp_header(cls, dst_ip:int, src_port:str, dst_port:int) -> bytes:
        fields:list      = list(cls._BASE_TCP_FIELDS)
        fields[0:2]      = [src_port, dst_port]
        tcp_header:bytes = cls._TCP_STRUCT.pack(*fields)
        
        pseudo_hdr:bytes = Layer_4_Utils.pseudo_header(dst_ip, socket.IPPROTO_TCP, len(tcp_header))
        checksum:int     = Layer_4_Utils.checksum(pseudo_hdr + tcp_header)

        fields[-2]       = checksum
        tcp_header:bytes = cls._TCP_STRUCT.pack(*fields)

        return tcp_header