# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket, random, time, sys
from arg_parser  import Argument_Manager as ArgParser
from sniffer     import Sniffer
from net_info    import get_ports
from pkt_sender  import send_layer_3_packet
from pkt_builder import Packet
from type_hints  import Raw_Packet
from display     import *


class Port_Scanner:

    STATUS = {
        'SYN-ACK':  green('Opened'),
        'SYN':      yellow('Potentially Open'),
        'RST-ACK':  red('Closed'),
        'FIN':      red('Connection Closed'),
        'RST':      red('Reset'),
        'Filtered': red('Filtered')
    }

    __slots__ = ('_target_ip', '_args', '_port_description', '_target_ports', '_ports_to_sniff', '_packets', '_responses')

    def __init__(self, parser_manager:ArgParser) -> None:
        self._target_ip:str            = None
        self._args:dict                = None
        self._port_description:dict    = None
        self._target_ports:list[int]   = None
        self._ports_to_sniff:list[int] = None
        self._packets:list[Raw_Packet] = None
        self._responses:list[dict]     = None
        self._get_argument_and_flags(parser_manager)


    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        return False


    def _get_argument_and_flags(self, parser_manager:ArgParser) -> None:
        self._target_ip  = socket.gethostbyname(parser_manager.host)
        self._args = {
            'show':   parser_manager.show,
            'port':   parser_manager.port,
            'all':    parser_manager.all,
            'random': parser_manager.random,
            'delay':  parser_manager.delay,
        }


    def _execute(self) -> None:
        try:
            self._prepare_ports()
            self._get_packets()
            self._send_and_receive()
            self._display_result()
        except KeyboardInterrupt:   print(f'\n{red("Process stopped")}')
        except ValueError as error: print(f'{yellow("Error")}: {error}')
        except Exception as error:  print(unexpected_error(error))


    def _prepare_ports(self) -> None:
        if self._args['port']:  self._port_description = get_ports(self._args['port'])
        elif self._args['all']: self._port_description = get_ports()
        else:                   self._port_description = get_ports('common')
        
        self._target_ports = [port for port in self._port_description.keys()]
        
        if self._args['random']:
            random.shuffle(self._target_ports)



    def _get_packets(self) -> None:
        self._packets, self._ports_to_sniff = Packet()._get_tcp_packets(self._target_ip, self._target_ports)



    def _send_and_receive(self) -> None:
        with Sniffer('IP', self._ports_to_sniff) as sniffer:
            self._send_packets()
            time.sleep(3)
            self._responses = sniffer._get_result()



    def _send_packets(self) -> None:
        delay_list = self._get_delay_time_list()
        print(self._packets)
        index      = 1
        for delay, packet, port in zip(delay_list, self._packets, self._target_ports):
            send_layer_3_packet(packet, self._target_ip, port)
            sys.stdout.write(f'\rPacket sent: {index}/{len(self._packets)} >> delay {delay:.2f}')
            sys.stdout.flush()
            time.sleep(delay)
            index += 1
        print('\n')



    def _get_delay_time_list(self) -> list[int]:
        if   self._args['delay'] is False: return [0.0 for _ in range(len(self._packets) - 1)] + [2.0]
        elif self._args['delay'] is True:  return [random.uniform(0.5, 2) for _ in range(len(self._packets))]

        values = [float(value) for value in self._args['delay'].split('-')]
        if len(values) > 1:
            return [random.uniform(values[0], values[1]) for _ in range(len(self._packets))]
        return [values[0] for _ in range(len(self._packets))]



    def _display_result(self) -> None:
        for pkt_info in self._responses:
            if pkt_info['flags'] != 'SYN-ACK' and self._args['show'] is False:
                continue
            flags       = pkt_info['flags']
            status      = self.STATUS.get(flags)
            port        = pkt_info['port']
            description = self._port_description[port]
            print(f'Status: {status:>17} -> {port:>5} - {description}')
