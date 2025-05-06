# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import struct
from ip_dissector     import IP_Dissector
from tcp_dissector    import TCP_Dissector
from utils.type_hints import Raw_Packet


class Packet_Dissector(IP_Dissector, TCP_Dissector):

    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = object().__new__(cls)
        return cls._instance



    __slots__ = ('_packet', '_ip_header')

    def __init__(self) -> None:
        self._packet:memoryview    = None
        self._ip_header:memoryview = None



    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        self.__class__._instance = None
        return False



    def process_packet(self, raw_packet:Raw_Packet) -> None:
        self._packet    = memoryview(raw_packet)
        self._ip_header = super().get_ip_header(self._packet)
        protocol:int    = super().get_protocol(self._ip_header)

        match protocol:
            case 1: return self._dissect_icmp_packet()
            case 6: return self._dissect_tcp_packet()
            case _: return None

    

    def _dissect_tcp_packet(self) -> dict:
        try:
            source_ip:str    = super().get_source_ip(self._ip_header)
            tcp_header:tuple = super().get_tcp_header(self._packet, self._ip_header)
            source_port:int  = super().get_tcp_source_port(tcp_header)
            tcp_flags:str    = super().get_tcp_flags(tcp_header)
            return {'ip':source_ip, 'port': source_port, 'flags': tcp_flags, 'protocol': 'TCP'}
        except (IndexError, struct.error, ValueError):
            return None



    def _dissect_icmp_packet(self) -> dict:
        try:
            source_mac:str = self._get_source_mac_address(self._packet)
            source_ip:str  = super().get_source_ip(self._ip_header)
            return {'ip': source_ip, 'mac': source_mac, 'protocol': 'ICMP'}
        except (IndexError, struct.error, ValueError):
            return None



    @staticmethod
    def _get_source_mac_address(packet:memoryview) -> str:
        return ":".join("%02x" % b for b in packet[6:12])
