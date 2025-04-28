# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import time
import random
from sniffing.sniffer          import Sniffer
from sniffing.packet_builder   import ICMP, create_tcp_ip_packet
from sniffing.packet_sender    import send_ping, send_layer_3_packet
from sniffing.packet_dissector import Packet_Dissector
from utils.network_info        import get_ip_range, get_host_name, get_random_ports
from utils.type_hints          import Raw_Packet


class Network_Mapper:

    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = object().__new__(cls)
        return cls._instance



    __slots__ = ('_responses')

    def __init__(self, _) -> None:
        self._responses:list|dict = None
    


    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        return False



    def _execute(self) -> None:
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
            self._responses = sniffer._get_packets()
    


    @staticmethod
    def _send_packets(source_ports:list) -> None:
        ICMP_PACKET:Raw_Packet = ICMP()
        for ip in get_ip_range():
            random_src_port:int   = random.choice(source_ports)
            tcp_packet:Raw_Packet = create_tcp_ip_packet(ip, 80, random_src_port)
            send_ping(ICMP_PACKET, ip)
            send_layer_3_packet(tcp_packet, ip, 80)



    def _process_responses(self) -> None:
        with Packet_Dissector() as dissector:
            for packet in self._responses:
                pkt_info:dict = dissector._process_packet(packet)
                self._update_data(pkt_info)

    

    def _update_data(self, pkt_info:dict) -> None:
        ip:str          = pkt_info['ip']
        mac_address:str = pkt_info['mac'] if 'mac' in pkt_info else None
        protocol:str    = pkt_info['protocol'] if 'protocol' in pkt_info else None

        if ip not in self._responses:
            self._responses[ip] = {'mac': 'Unknown', 'protocols': []}
        
        if mac_address:
            self._responses[ip]['mac'] = mac_address
        
        if protocol:
            self._responses[ip]['protocols'].append(protocol)



    def _display_result(self) -> None:
        print(f'IP Address{8*" "}MAC Address{9*" "}Protocols   Hostname')
        for ip in self._responses:
            protocols:str   = '-'.join(ip['protocols'])
            mac_address:str = self._responses[ip]['mac']
            print(f'{ip:<15} - {mac_address} - {protocols:<10} - {get_host_name(ip)}')
        print(f'Total: {len(self._responses)} active hosts')