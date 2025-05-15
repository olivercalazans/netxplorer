# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import struct
import sys
from dissector.ip_dissector  import IP_Dissector
from dissector.tcp_dissector import TCP_Dissector
from models.data             import Data


class Packet_Dissector(IP_Dissector, TCP_Dissector):

    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = object().__new__(cls)
        return cls._instance



    __slots__ = ('_data', '_packet', '_ip_header')

    def __init__(self, data:Data) -> None:
        self._data:Data            = data
        self._packet:memoryview    = None
        self._ip_header:memoryview = None



    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        self.__class__._instance = None
        return False



    def dissect_packets(self) -> None:
        len_packets:int       = len(self._data.raw_packets)
        dissected_packets:int = 0
        
        while self._data.raw_packets:
            dissected_packets += 1
            self._display_progress(dissected_packets, len_packets)

            self._packet       = memoryview(self._data.raw_packets.pop())
            self._ip_header    = super().get_ip_header(self._packet)
            protocol_byte:int  = super().get_protocol(self._ip_header)

            match protocol_byte:
                case 1: protocol, packet_info = self._dissect_icmp_packet()
                case 6: protocol, packet_info = self._dissect_tcp_packet()
                case _: continue

            if protocol is None: continue

            self._data.add_packet(protocol, packet_info)
        sys.stdout.write('\n')

    

    @staticmethod
    def _display_progress(index:int, len_ports:int) -> None:
        sys.stdout.write(f'\rDissected packets: {index}/{len_ports}')
        sys.stdout.flush()



    def _dissect_tcp_packet(self) -> tuple[str, tuple] | None:
        try:
            source_ip:str    = super().get_source_ip(self._ip_header)
            tcp_header:tuple = super().get_tcp_header(self._packet, self._ip_header)
            source_port:int  = super().get_tcp_source_port(tcp_header)
            flag_status:str  = super().get_tcp_flag_status(tcp_header)

            if flag_status is None: return None, None

            return 'TCP', (source_ip, source_port, flag_status)
        except (IndexError, struct.error, ValueError):
            return None, None



    def _dissect_icmp_packet(self) -> tuple[str, tuple] | None:
        try:
            source_mac:str = self._get_source_mac_address(self._packet)
            source_ip:str  = super().get_source_ip(self._ip_header)
            return 'ICMP', (source_ip, source_mac)
        except (IndexError, struct.error, ValueError):
            return None, None



    @staticmethod
    def _get_source_mac_address(packet:memoryview) -> str:
        return ":".join("%02x" % b for b in packet[6:12])
