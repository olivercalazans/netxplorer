# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import random
import time
import sys
from dissector.dissector      import Packet_Dissector
from models.data              import Data
from pkt_build.packet_sender  import send_layer_3_packet
from pkt_build.packet_builder import Packet_Builder
from sniffing.sniffer         import Sniffer
from utils.network_info       import get_host_name
from utils.port_set           import Port_Set
from utils.type_hints         import Raw_Packet


class Port_Scanner:
    
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = object().__new__(cls)
        return cls._instance


    __slots__ = ('_data')

    def __init__(self, data:Data) -> None:
        self._data:Data = data



    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        self.__class__._instance = None
        return False



    def execute(self) -> None:
        try:
            self._prepare_ports()
            self._send_and_receive()
            self._process_result()
            self._display_result()
        except KeyboardInterrupt:  print('Process stopped')
        except Exception as error: print(f'ERROR: {error}')



    def _prepare_ports(self) -> None:
        self._data.target_ports = self._data.arguments['ports'] or 'TCP'
        
        if self._data.arguments['random']:
            random.shuffle(self._data.target_ports)



    def _send_and_receive(self) -> None:
        with Sniffer(self._data, 'TCP') as sniffer:
            self._send_packets()
            time.sleep(3)
            sniffer.stop_sniffing()



    def _send_packets(self) -> None:
        delay_list:list = self._get_delay_time_list()
        len_ports:int   = len(self._data.target_ports)
        index:int       = 1

        for delay, dst_port in zip(delay_list, self._data.target_ports):
            packet:Raw_Packet = Packet_Builder.get_tcp_ip_packet(self._data.target_ip, dst_port)
            send_layer_3_packet(packet, self._data.target_ip, dst_port)
            
            self._display_progress(index, len_ports, delay)
            time.sleep(delay)
            index += 1
            
        sys.stdout.write('\n')

    
    
    @staticmethod
    def _display_progress(index:int, len_ports:int, delay:float) -> None:
        sys.stdout.write(f'\rPackets sent: {index}/{len_ports} >> delay {delay:.2f}')
        sys.stdout.flush()



    def _get_delay_time_list(self) -> list[int]:
        match self._data.arguments['delay']:
            case False: return [0.05 for _ in range(len(self._data.target_ports))]
            case True:  return [random.uniform(0.5, 2) for _ in range(len(self._data.target_ports))]
            case _:
                
                values = [float(value) for value in self._data.arguments['delay'].split('-')]

                if len(values) > 1:
                    return [random.uniform(values[0], values[1]) for _ in range(len(self._data.target_ports))]

                return [values[0] for _ in range(len(self._data.target_ports))]



    def _process_result(self) -> None:
        with Packet_Dissector(self._data) as dissector:
            dissector.dissect_packets()



    def _display_result(self) -> None:
        print(f'>> IP: {self._data.target_ip} - Hostname: {get_host_name(self._data.target_ip)}')
        
        open_ports = 0
        for _, port, status in self._data.responses['TCP']:
            description:str = Port_Set.get_tcp_port_description(port)
            open_ports += 1
            print(f'Status: {status} -> {port:>5} - {description}')
        
        print(f'Open ports: {open_ports}/{len(self._data.target_ports)}')