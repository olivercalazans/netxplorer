# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import struct, socket
from type_hints import Raw_Packet


class Dissector:

    FLAG_MAP = {
            0b00010010: "SA",  # SYN-ACK (0b00000010 + 0b00010000)
            0b00000010: "S",   # SYN
            0b00010100: "RA",  # RST-ACK (0b00000100 + 0b00010000)
            0b00000100: "R",   # RST
            0b00000001: "F"    # FIN
        }

    __slots__ = ('_packet', '_ip_header', '_tcp_header', '_source_ip', '_source_port', '_flags')

    def __init__(self):
        self._packet:Raw_Packet = None
        self._ip_header:bytes   = None
        self._tcp_header:bytes  = None
        self._source_ip:str     = None
        self._source_port:int   = None
        self._flags:str|None    = None


    def _dissect(self, packets:list[Raw_Packet]) -> list[dict|None]:
        return [self._dissect_tcp_ip_packet(pkt) for pkt in packets]


    def _dissect_tcp_ip_packet(self, packet:Raw_Packet) -> dict|None:
            try:
                self._packet = memoryview(packet)
                self._get_ip_header()
                self._get_tcp_header()
                self._get_source_ip()
                self._get_source_port()
                self._get_tcp_flags()
                return {'ip': self._source_ip, 'port': self._source_port, 'flags': self._flags}
            except (IndexError, struct.error, ValueError):
                return None


    def _get_ip_header(self) -> bytes:
        ip_header       = self._packet[14:34]
        ip_header       = struct.unpack('!BBHHHBBH4s4s', ip_header)
        self._ip_header = ip_header


    def _get_tcp_header(self) -> bytes:
        ihl              = (self._ip_header[0] & 0x0F) * 4
        tcp_header_start = 14 + ihl
        tcp_header       = self._packet[tcp_header_start:tcp_header_start + 20]
        self._tcp_header = struct.unpack('!HHLLBBHHH', tcp_header)


    def _get_source_ip(self) -> None:
        self._source_ip = socket.inet_ntoa(self._ip_header[8])


    def _get_source_port(self) -> None:
        self._source_port = self._tcp_header[0]


    def _get_tcp_flags(self) -> None:
        flags       = self._tcp_header[5]
        self._flags = self.FLAG_MAP.get(flags & (0b00111111), None)
