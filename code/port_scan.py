# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import random
import time
import sys
from socket        import gethostbyname
from sniffer       import Sniffer
from net_info      import get_ports, get_host_name
from pkt_sender    import send_layer_3_packet
from pkt_builder   import TCP, IP
from pkt_dissector import dissect_tcp_packet
from type_hints    import Raw_Packet
from display       import *


class Port_Scanner:

    STATUS = {
        'SYN-ACK':  green('Opened'),
        'SYN':      yellow('Potentially Open'),
        'RST-ACK':  red('Closed'),
        'FIN':      red('Connection Closed'),
        'RST':      red('Reset'),
        'Filtered': red('Filtered')
    }

    __slots__ = ('_target_ip', '_args', '_target_ports', '_responses')

    def __init__(self, arguments:dict) -> None:
        self._target_ip:str        = gethostbyname(arguments.pop('host'))
        self._args:dict            = arguments
        self._target_ports:dict    = None
        self._responses:list[dict] = None



    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        return False



    def _execute(self) -> None:
        try:
            self._prepare_target_ports()
            self._send_and_receive()
            self._display_result()
        except KeyboardInterrupt:   display_process_stopped()
        except ValueError as error: display_error(error)
        except Exception as error:  display_unexpected_error(error)



    def _prepare_target_ports(self) -> None:
        if self._args['port']:  self._target_ports = get_ports(self._args['port'])
        elif self._args['all']: self._target_ports = get_ports()
        else:                   self._target_ports = get_ports('common')
        
        if self._args['random']:
            random_list        = random.sample(list(self._target_ports.items()), len(self._target_ports))
            self._target_ports = dict(random_list)



    def _send_and_receive(self) -> None:
        src_ports = ports_to_sniff = [random.randint(10000, 65535) for _ in self._target_ports]
        with Sniffer('TCP', ports_to_sniff) as sniffer:
            self._send_packets(src_ports)
            time.sleep(3)
            self._responses = sniffer._get_packets()



    def _send_packets(self, src_ports:list[int]) -> None:
        delay_list = self._get_delay_time_list()
        index      = 1
        for delay, src_port, dst_port in zip(delay_list, src_ports, self._target_ports):
            packet = self._create_packet(src_port, dst_port)
            send_layer_3_packet(packet, self._target_ip, dst_port)

            sys.stdout.write(f'\rPacket sent: {index}/{len(self._target_ports)} >> delay {delay:.2f}')
            sys.stdout.flush()
            
            time.sleep(delay)
            index += 1
        sys.stdout.write('\n')

    

    def _create_packet(self, src_port:int, dst_port:int) -> Raw_Packet:
        ip_header  = IP(self._target_ip)
        tcp_header = TCP(src_port, dst_port, self._target_ip)
        return Raw_Packet(ip_header + tcp_header)



    def _get_delay_time_list(self) -> list[int]:
        if   self._args['delay'] is False: return [0.0 for _ in range(len(self._target_ports))]
        elif self._args['delay'] is True:  return [random.uniform(0.5, 2) for _ in range(len(self._target_ports))]

        values = [float(value) for value in self._args['delay'].split('-')]
        if len(values) > 1:
            return [random.uniform(values[0], values[1]) for _ in range(len(self._target_ports))]
        return [values[0] for _ in range(len(self._target_ports))]



    def _display_result(self) -> None:
        self._display_header(self._target_ip)
        open_ports = 0
        for packet in self._responses:
            port, flags = dissect_tcp_packet(packet)

            if flags != 'SYN-ACK' and self._args['show'] is False:
                continue

            if flags == 'SYN-ACK': open_ports += 1
            status      = self.STATUS.get(flags)
            description = self._target_ports[port]
            print(f'Status: {status:>17} -> {port:>5} - {description}')
        print(f'Open ports: {open_ports}/{len(self._target_ports)}')

    

    @staticmethod
    def _display_header(ip:str) -> None:
        hostname = get_host_name(ip)
        print(f'IP: {ip} - Hostname: {hostname}')
