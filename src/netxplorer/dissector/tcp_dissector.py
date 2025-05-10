# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import struct


class TCP_Dissector:

    TCP_HEADER_STRUCT:struct.Struct = struct.Struct('!HHLLBBHHH')
    TCP_FLAG_STATUS:dict = {
            0b00010010: 'OPENED', #.......: SYN-ACK > (0b00000010 + 0b00010000)
            0b00000010: 'Potencially',#...: SYN
            0b00010100: None, #...........: RST-ACK > (0b00000100 + 0b00010000)
            0b00000100: None, #...........: RST
            0b00000001: None #............: FIN
    }


    @classmethod
    def get_tcp_header(cls, packet:memoryview, ip_header:memoryview) -> tuple[int, bytes]:
        start, end = cls._calculate_tcp_header_length(ip_header)
        return cls.TCP_HEADER_STRUCT.unpack(packet[start:end])


    @staticmethod
    def _calculate_tcp_header_length(ip_header:memoryview) -> tuple[int, int]:
        ihl:int   = (ip_header[0] & 0x0F) * 4
        start:int = 14 + ihl
        end:int   = start + 20
        return start, end
    

    @staticmethod
    def get_tcp_source_port(tcp_header:memoryview) -> memoryview:
        return tcp_header[0]
    

    @classmethod
    def get_tcp_flag_status(cls, tcp_header:tuple) -> int:
        return cls.TCP_FLAG_STATUS.get(tcp_header[5] & (0b00111111), None)