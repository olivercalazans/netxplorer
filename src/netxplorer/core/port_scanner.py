# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import random
import time
import sys
from models.data              import Data
from sniffing.sniffer         import Sniffer
from pkt_build.packet_sender  import send_layer_3_packet
from pkt_build.packet_builder import Packet_Builder
from dissector.dissector      import Packet_Dissector
from utils.network_info       import get_host_name, get_random_ports
from utils.port_set           import Port_Set
from utils.type_hints         import Raw_Packet


class Port_Scanner:
    
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = object().__new__(cls)
        return cls._instance



    STATUS = {
        'SYN-ACK':  'OPENED',
        'SYN':      'Potentially',
        'RST-ACK':  'Closed',
        'FIN':      'Connection Closed',
        'RST':      'Reset',
        'Filtered': 'Filtered'
    }

    __slots__ = ('_data', '_responses')

    def __init__(self, data:Data) -> None:
        self._data:Data           = data
        self._responses:list|dict = None



    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        self.__class__._instance = None
        return False



    def execute(self) -> None:
        try:
            self._prepare_target_ports()
            self._send_and_receive()
            self._process_result()
            self._display_result()
        except KeyboardInterrupt:  print('Process stopped')
        except Exception as error: print(f'ERROR: {error}')



    def _prepare_target_ports(self) -> None:
        if self._data.arguments['ports']: self._data.ports = self._data.arguments['ports']
        elif self._data.arguments['all']: self._data.ports = 'all'
        else:                             self._data.ports = 'common'
        
        if self._data.arguments['random']:
            random_list:list  = random.sample(list(self._data.ports.items()), len(self._data.ports))
            self._data.ports = dict(random_list)



    def _send_and_receive(self) -> None:
        src_ports = ports_to_sniff = get_random_ports(len(self._data.ports))
        with Sniffer('TCP', ports_to_sniff) as sniffer:
            self._send_packets(src_ports)
            time.sleep(3)
            self._responses = sniffer.get_packets()



    def _send_packets(self, src_ports:list[int]) -> None:
        delay_list:list = self._get_delay_time_list()
        len_ports:int   = len(self._data.ports)
        index:int       = 1
        for delay, src_port, dst_port in zip(delay_list, src_ports, self._data.ports):
            packet:Raw_Packet = Packet_Builder.get_tcp_ip_packet(self._data.target_ip, src_port, dst_port)
            send_layer_3_packet(packet, self._data.target_ip, dst_port)
            self._display_progress(index, len_ports, delay)
            time.sleep(delay)
            index += 1
            
        sys.stdout.write('\n')

    
    
    @staticmethod
    def _display_progress(index:int, len_ports:int, delay:float) -> None:
        sys.stdout.write(f'\rPacket sent: {index}/{len_ports} >> delay {delay:.2f}')
        sys.stdout.flush()



    def _get_delay_time_list(self) -> list[int]:
        if   self._data.arguments['delay'] is False: return [0.0 for _ in range(len(self._data.ports))]
        elif self._data.arguments['delay'] is True:  return [random.uniform(0.5, 2) for _ in range(len(self._data.ports))]

        values = [float(value) for value in self._data.arguments['delay'].split('-')]
        if len(values) > 1:
            return [random.uniform(values[0], values[1]) for _ in range(len(self._data.ports))]
        return [values[0] for _ in range(len(self._data.ports))]



    def _process_result(self) -> None:
        with Packet_Dissector() as dissector:
            results:dict = {'TCP':[]}
            for protocol in self._responses:
                for packet in self._responses[protocol]:
                    pkt_info:dict            = dissector.process_packet(packet)
                    _, port, flags, protocol = pkt_info.values()
                    results[protocol].append((port, flags))

        self._responses = results



    def _display_result(self) -> None:
        print(f'>> IP: {self._data.target_ip} - Hostname: {get_host_name(self._data.target_ip)}')
        open_ports = 0
        for protocol in self._responses:
            for port, flags in self._responses[protocol]:
                if flags != 'SYN-ACK' and self._data.arguments['show'] is False:
                    continue

                if flags == 'SYN-ACK':
                    open_ports += 1
                
                status      = self.STATUS.get(flags)
                description = self._data.ports[port]
                print(f'Status: {status:>8} -> {port:>5} - {description}')
        print(f'Open ports: {open_ports}/{len(self._data.ports)}')