# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import random
import time
import sys
from models.data               import Data
from sniffing.sniffer          import Sniffer
from sniffing.packet_sender    import send_layer_3_packet
from sniffing.packet_builder   import create_tcp_ip_packet
from sniffing.packet_dissector import Packet_Dissector
from utils.network_info        import get_ports, get_host_name
from utils.type_hints          import Raw_Packet


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
        self._data:Data      = data
        self._responses:list = None



    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        return False



    def _execute(self) -> None:
        try:
            self._prepare_target_ports()
            self._send_and_receive()
            self._display_result()
        except KeyboardInterrupt:  print('Process stopped')
        except Exception as error: print(f'ERROR: {error}')



    def _prepare_target_ports(self) -> None:
        if self._data._arguments['ports']: self._data._ports = get_ports(self._data._arguments['ports'])
        elif self._data._arguments['all']: self._data._ports = get_ports()
        else:                              self._data._ports = get_ports('common')
        
        if self._data._arguments['random']:
            random_list:list  = random.sample(list(self._data._ports.items()), len(self._data._ports))
            self._data._ports = dict(random_list)



    def _send_and_receive(self) -> None:
        src_ports = ports_to_sniff = [random.randint(10000, 65535) for _ in self._data._ports]
        with Sniffer('TCP', ports_to_sniff) as sniffer:
            self._send_packets(src_ports)
            time.sleep(3)
            self._responses = sniffer._get_packets()



    def _send_packets(self, src_ports:list[int]) -> None:
        delay_list:list = self._get_delay_time_list()
        len_ports:int   = len(self._data._ports)
        index:int       = 1

        for delay, src_port, dst_port in zip(delay_list, src_ports, self._data._ports):
            packet:Raw_Packet = create_tcp_ip_packet(self._data._target_ip, dst_port, src_port)
            send_layer_3_packet(packet, self._data._target_ip, dst_port)
            self._display_progress(index, len_ports, delay)
            time.sleep(delay)
            index += 1
            
        sys.stdout.write('\n')

    
    
    @staticmethod
    def _display_progress(index:int, len_ports:int, delay:float) -> None:
        sys.stdout.write(f'\rPacket sent: {index}/{len_ports} >> delay {delay:.2f}')
        sys.stdout.flush()



    def _get_delay_time_list(self) -> list[int]:
        if   self._data._arguments['delay'] is False: return [0.0 for _ in range(len(self._data._ports))]
        elif self._data._arguments['delay'] is True:  return [random.uniform(0.5, 2) for _ in range(len(self._data._ports))]

        values = [float(value) for value in self._data._arguments['delay'].split('-')]
        if len(values) > 1:
            return [random.uniform(values[0], values[1]) for _ in range(len(self._data._ports))]
        return [values[0] for _ in range(len(self._data._ports))]



    def _display_result(self) -> None:
        print(f'>> IP: {self._data._target_ip} - Hostname: {get_host_name(self._data._target_ip)}')
        open_ports = 0
        with Packet_Dissector() as dissector:
            for packet in self._responses:
                port, flags = dissector._dissect_tcp_packet(packet)

                if flags != 'SYN-ACK' and self._data._arguments['show'] is False:
                    continue

                if flags == 'SYN-ACK': open_ports += 1
                status      = self.STATUS.get(flags)
                description = self._data._ports[port]
                print(f'Status: {status:>8} -> {port:>5} - {description}')
        print(f'Open ports: {open_ports}/{len(self._data._ports)}')