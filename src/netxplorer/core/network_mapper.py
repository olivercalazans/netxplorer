# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import time
import random
from pkt_build.icmp          import ICMP
from pkt_build.tcp           import TCP
from pkt_build.packet_sender import send_ping, send_layer_3_packet
from sniffing.sniffer        import Sniffer
from dissector.dissector     import Packet_Dissector
from utils.network_info      import get_ip_range, get_host_name, get_random_ports
from utils.type_hints        import Raw_Packet


class Network_Mapper:

    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = object().__new__(cls)
        return cls._instance



    __slots__ = ('_responses', '_results')

    def __init__(self, _) -> None:
        self._responses:list = None
        self._results:dict   = {}
    


    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        self.__class__._instance = None
        return False



    def execute(self) -> None:
        try:
            self._perform_mapping()
            self._process_responses()
            self._display_result()
        except KeyboardInterrupt:  print('Process stopped')
        except Exception as error: print(f'ERROR: {error}')



    def _perform_mapping(self) -> None:
        source_ports:list = get_random_ports(5)
        with Sniffer('TCP-ICMP', source_ports) as sniffer:
            self._send_packets(source_ports)
            time.sleep(3)
            self._responses = sniffer.get_packets()
    


    @staticmethod
    def _send_packets(source_ports:list) -> None:
        icmp_packet:Raw_Packet = ICMP().get_packet()
        tcp:TCP                = TCP()
        for ip in get_ip_range():
            random_src_port:int   = random.choice(source_ports)
            tcp_packet:Raw_Packet = tcp.get_tcp_ip_packet(ip, 80, random_src_port)
            send_ping(icmp_packet, ip)
            send_layer_3_packet(tcp_packet, ip, 80)



    def _process_responses(self) -> None:
        with Packet_Dissector() as dissector:
            for packet in self._responses:
                pkt_info:dict = dissector.process_packet(packet)
                self._update_data(pkt_info)

    

    def _update_data(self, pkt_info:dict) -> None:
        ip:str          = pkt_info['ip']
        mac_address:str = pkt_info['mac'] if 'mac' in pkt_info else None
        protocol:str    = pkt_info['protocol'] if 'protocol' in pkt_info else None

        if ip not in self._results:
            self._results[ip] = {'mac': 'Unknown', 'protocols': []}

        if mac_address:
            self._results[ip]['mac'] = mac_address
        
        if protocol:
            self._results[ip]['protocols'].append(protocol)



    def _display_result(self) -> None:
        print(f'#IP Address{7*" "}#MAC Address{8*" "}#Protocols   Hostname')
        for ip, info in self._results.items():
            protocols:str   = '-'.join(sorted(info['protocols']))
            mac_address:str = info['mac']
            print(f'{ip:<18}{mac_address:<20}{protocols:<13}{get_host_name(ip)}')
        print(f'Total: {len(self._results)} active hosts')