# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket
from struct                      import Struct
from packet.layers.layer_4_utils import Layer_4_Utils
from utils.port_set              import Port_Set


class TCP:

    _TCP_HEADER_STRUCT:Struct = Struct('!HHLLBBHHH')


    # BUILDER ================================================================================================

    _BASE_TCP_FIELDS: tuple   = (
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
    def create_tcp_header(cls, dst_ip:int, dst_port:int) -> bytes:
        src_port:int     = Port_Set.get_random_port()
        
        fields:list      = list(cls._BASE_TCP_FIELDS)
        fields[0:2]      = [src_port, dst_port]
        tcp_header:bytes = cls._TCP_HEADER_STRUCT.pack(*fields)
        
        pseudo_hdr:bytes = Layer_4_Utils.pseudo_header(dst_ip, socket.IPPROTO_TCP, len(tcp_header))
        checksum:int     = Layer_4_Utils.checksum(pseudo_hdr + tcp_header)

        fields[-2]       = checksum
        tcp_header:bytes = cls._TCP_HEADER_STRUCT.pack(*fields)

        return tcp_header
    


    # DISSECTOR ==============================================================================================

    TCP_FLAG_STATUS:dict = {
            0b00010010: 'OPENED', #.......: SYN-ACK > (0b00000010 + 0b00010000)
            0b00000010: 'Potencially',#...: SYN
            0b00010100: 'Closed', #.......: RST-ACK > (0b00000100 + 0b00010000)
            0b00000100: 'Closed', #.......: RST
            0b00000001: None #............: FIN
    }


    @classmethod
    def get_tcp_header(cls, packet:memoryview, ip_header_len:int) -> tuple[int, bytes]:
        len_ether_header:int = 14
        start:int            = len_ether_header + ip_header_len
        end:int              = start + 20
        return cls._TCP_HEADER_STRUCT.unpack(packet[start:end])
    

    @staticmethod
    def get_tcp_source_port(tcp_header:memoryview) -> memoryview:
        return tcp_header[0]
    

    @classmethod
    def get_tcp_flag_status(cls, tcp_header:tuple) -> int:
        return cls.TCP_FLAG_STATUS.get(tcp_header[5] & (0b00111111), None)