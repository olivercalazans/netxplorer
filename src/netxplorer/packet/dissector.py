# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import struct
import sys
from models.data        import Data
from packet.layers.ip   import IP
from packet.layers.icmp import ICMP
from packet.layers.tcp  import TCP
from packet.layers.udp  import UDP


class Packet_Dissector():

    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = object().__new__(cls)
        return cls._instance



    __slots__ = ('_data', '_packet', '_ip_header', '_len_ip_header', '_other_packets')

    def __init__(self, data:Data) -> None:
        self._data:Data            = data
        self._packet:memoryview    = None
        self._ip_header:memoryview = None
        self._len_ip_header:int    = None
        self._other_packets:list   = []



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

            self._packet      = memoryview(self._data.raw_packets.pop())
            self._dissect_ip_header()
            protocol_byte:int = IP.get_protocol(self._ip_header)

            match protocol_byte:
                case 1: protocol, packet_info = self._dissect_icmp_header()
                case 6: protocol, packet_info = self._dissect_tcp_header()
                case _: continue

            if protocol is None: continue

            self._data.add_packet(protocol, packet_info)
        sys.stdout.write('\n')

        if self._other_packets: self._dissect_other_packets()
        



    def _dissect_other_packets(self) -> None:
        len_other_packets:int = len(self._other_packets)
        dissected_packets:int = 0

        while self._other_packets:
            dissected_packets += 1
            self._display_progress(dissected_packets, len_other_packets, '(Others)')

            self._packet:memoryview = memoryview(self._other_packets.pop())
            self._dissect_ip_header(0)
            protocol, packet_info   = self._dissect_udp_header()
            
            if protocol is None: continue

            self._data.add_packet(protocol, packet_info)
        sys.stdout.write('\n')

    

    @staticmethod
    def _display_progress(index:int, len_ports:int, description:str='') -> None:
        sys.stdout.write(f'\rDissected packets: {index}/{len_ports} {description}')
        sys.stdout.flush()



    # LAYERS ===============================================================================

    @staticmethod
    def _get_source_mac_address(packet:memoryview) -> str:
        return ":".join("%02x" % b for b in packet[6:12])



    def _dissect_ip_header(self, len_ether_header:int=14) -> None:
        self._ip_header     = IP.get_ip_header(self._packet, len_ether_header)
        self._len_ip_header = len(self._ip_header)



    def _dissect_tcp_header(self) -> tuple[str, tuple] | None:
        try:
            source_ip:str    = IP.get_source_ip(self._ip_header)
            tcp_header:tuple = TCP.get_tcp_header(self._packet, self._len_ip_header)
            source_port:int  = TCP.get_tcp_source_port(tcp_header)
            flag_status:str  = TCP.get_tcp_flag_status(tcp_header)

            if flag_status is None: return None, None

            return 'TCP', (source_ip, source_port, flag_status)
        except (IndexError, struct.error, ValueError):
            return None, None
        
    

    def _dissect_udp_header(self) -> int | None:
        try: 
            udp_header:memoryview = UDP.get_udp_header(self._packet, self._len_ip_header)
            dst_port:int          = UDP.get_udp_destiny_port(udp_header)
            return 'UDP', dst_port
        except:
            return None, None



    def _dissect_icmp_header(self) -> tuple[str, tuple] | None:
        try:
            source_mac:str         = self._get_source_mac_address(self._packet)
            source_ip:str          = IP.get_source_ip(self._ip_header)
            icmp_header:memoryview = ICMP.get_icmp_header(self._packet, self._len_ip_header)
            icmp_type, icmp_code   = ICMP.get_icmp_type_and_code(icmp_header)

            if icmp_type == 3 and icmp_code == 3:
                payload:bytes = ICMP.extract_icmp_payload(self._packet, self._len_ip_header)
                self._other_packets.append(payload)

            return 'ICMP', (source_ip, source_mac)
        except (IndexError, struct.error, ValueError):
            return None, None