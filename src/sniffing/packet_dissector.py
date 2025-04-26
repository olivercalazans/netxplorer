# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import struct
import socket
from type_hints import Raw_Packet


class Packet_Dissector:

    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = object().__new__(cls)
        return cls._instance



    __slots__ = ('_packet')

    def __init__(self) -> None:
        self._packet:Raw_Packet = None



    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        return False



    IP_HEADER_STRUCT  = struct.Struct('!BBHHHBBH4s4s')
    SOURCE_IP_STRUCT  = struct.Struct('4s')
    TCP_HEADER_STRUCT = struct.Struct('!HHLLBBHHH')
    TCP_FLAG_MAP      = {
            0b00010010: 'SYN-ACK', # (0b00000010 + 0b00010000)
            0b00000010: 'SYN',
            0b00010100: 'RST-ACK', # (0b00000100 + 0b00010000)
            0b00000100: 'RST',
            0b00000001: 'FIN'
        }



    @property
    def packet(self) -> Raw_Packet:
        return self._packet
    
    @packet.setter
    def packet(self, packet:Raw_Packet) -> None:
        self._packet = memoryview(packet)

    

    def _dissect_tcp_packet(self, packet:Raw_Packet) -> tuple[int, str]:
        try:
            self.packet      = packet
            tcp_header:tuple = self._get_tcp_header()
            source_port:int  = tcp_header[0]
            tcp_flags:str    = self._get_tcp_flags(tcp_header)
            return (source_port, tcp_flags)
        except (IndexError, struct.error, ValueError):
            return None



    def _dissect_icmp_packet(self, packet:Raw_Packet) -> str:
        try:
            self.packet    = packet
            source_mac:str = self._get_source_mac_address()
            source_ip:str  = self._get_source_ip()
            return source_ip, source_mac
        except (IndexError, struct.error, ValueError):
            return None



    def _get_source_mac_address(self) -> str:
        return ":".join("%02x" % b for b in self._packet[6:12])


    def _get_ip_header(self) -> memoryview:
        return self._packet[14:34]
    

    def _get_source_ip(self) -> str:
        ip_header = self._get_ip_header()
        raw_bytes = self.SOURCE_IP_STRUCT.unpack(ip_header[12:16])[0]
        return socket.inet_ntoa(raw_bytes)
    

    def _get_tcp_header(self) -> tuple[int, bytes]:
        start, end = self._calculate_tcp_header_length()
        return self.TCP_HEADER_STRUCT.unpack(self._packet[start:end])


    def _calculate_tcp_header_length(self) -> tuple[int, int]:
        ip_header = self._get_ip_header()
        ihl:int   = (ip_header[0] & 0x0F) * 4
        start:int = 14 + ihl
        end:int   = start + 20
        return start, end
    

    def _get_tcp_flags(self, tcp_header) -> int:
        return self.TCP_FLAG_MAP.get(tcp_header[5] & (0b00111111), 'Filtered')
