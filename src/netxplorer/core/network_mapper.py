# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...



import time
import sys
from models.data        import Data
from packet.dissector   import Packet_Dissector
from packet.builder     import Packet_Builder
from packet.sender      import send_ping, send_layer_3_packet
from sniffing.sniffer   import Sniffer
from utils.network_info import get_ip_range, get_host_name
from utils.type_hints   import Raw_Packet



class Network_Mapper:

    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = object().__new__(cls)
        return cls._instance



    __slots__ = ('_data', '_results')

    def __init__(self, data:Data) -> None:
        self._data:Data    = data
        self._results:dict = {}
    


    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        self.__class__._instance = None
        return False



    def execute(self) -> None:
        try:
            self._perform_mapping()
            self._process_packets()
            self._process_responses()
            self._display_result()
        except KeyboardInterrupt:  print('Process stopped')
        except Exception as error: print(f'ERROR: {error}')



    def _perform_mapping(self) -> None:
        with Sniffer(self._data, 'TCP-ICMP') as sniffer:
            self._send_packets()
            time.sleep(3)
            sniffer.stop_sniffing()
    


    def _send_packets(self) -> None:
        self._data.target_ip   = get_ip_range()
        total_ips:int          = len(self._data.target_ip)
        icmp_packet:Raw_Packet = Packet_Builder().build_packet('ICMP')
        
        for index ,ip in enumerate(self._data.target_ip, start=1):
            tcp_packet:Raw_Packet = Packet_Builder.build_packet('TCP', ip, 80)
            send_ping(icmp_packet, ip)
            send_layer_3_packet(tcp_packet, ip, 80)
            self._display_progress(index, total_ips)
            time.sleep(0.04)
        
        sys.stdout.write('\n')


    
    @staticmethod
    def _display_progress(index:int, total:int) -> None:
        sys.stdout.write(f'\rPackets sent: {index}/{total}')
        sys.stdout.flush()



    def _process_packets(self) -> None:
        with Packet_Dissector(self._data) as dissector:
            dissector.dissect_packets()

    

    def _process_responses(self) -> None:
        if self._data.responses['ICMP']:
            self._process_icmp_reponses()
        
        if self._data.responses['TCP']:
            self._process_tcp_responses()


    
    def _process_icmp_reponses(self) -> None:
        while self._data.responses['ICMP']:
            ip, mac_addr      = self._data.responses['ICMP'].pop()
            self._results[ip] = {'mac': mac_addr, 'protocols': ['ICMP']}


    
    def _process_tcp_responses(self) -> None:
        while self._data.responses['TCP']:
            ip, _, _ = self._data.responses['TCP'].pop()

            if ip not in self._results:
                self._results[ip] = {'mac': 'Unknown', 'protocols': ['TCP']}
                continue

            self._results[ip]['protocols'].append('TCP')



    def _display_result(self) -> None:
        print(f'IP Address{7*" "}MAC Address{8*" "}Protocols  Hostname')
        print(f'{"-" * 15}  {"-" * 17}  {"-" * 9}  {"-" * 8}')
        
        for ip, info in self._results.items():
            protocols:str   = '-'.join(sorted(info['protocols']))
            mac_address:str = info['mac']
        
            print(f'{ip:<16} {mac_address:<18} {protocols:<11}{get_host_name(ip)}')
        print(f'Total: {len(self._results)} active hosts')