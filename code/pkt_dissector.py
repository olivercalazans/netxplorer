# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import struct, socket
from type_hints import Raw_Packet


class Dissector:

    def __init__(self, packet:Raw_Packet):
        self._packet:Raw_Packet = packet
        self._ip_header:bytes   = None
        self._source_ip:str     = None
        self._tcp_header:bytes  = None
        self._source_port:int   = None


    def _dissect_tcp_ip_packet(self) -> dict|None:
            try:
                self._get_ip_header()
                self._get_source_ip()
                self._get_tcp_header()
                self._get_source_port()
                print(f"IP Packet: Source: {self._source_ip}, Source Port: {self._source_port}")
            except Exception:
                 return None


    def _get_ip_header(self) -> None:
        ip_header       = self._packet[14:34]
        ip_header       = struct.unpack('!BBHHHBBH4s4s', ip_header)
        self._ip_header = ip_header

    
    def _get_source_ip(self) -> None:
         self._source_ip = socket.inet_ntoa(self._ip_header[8])

    
    def _get_tcp_header(self) -> None:
        ihl              = (self._ip_header[0] & 0x0F) * 4
        tcp_header_start = 14 + ihl
        tcp_header       = self._packet[tcp_header_start:tcp_header_start + 20]
        self._tcp_header = struct.unpack('!HHLLBBHHH', tcp_header)

    
    def _get_source_port(self) -> None:
        self._source_port = self._tcp_header[0]