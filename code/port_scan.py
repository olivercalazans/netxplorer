# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket, random, time, sys
from arg_parser  import Argument_Manager as ArgParser
from sniffer     import Sniffer
from network     import get_ports, get_ip_range
from pkt_sender  import send_layer_3_packet
from pkt_builder import Packet
from type_hints  import Raw_Packet
from display     import *


class Port_Scanner:

    STATUS = {
        'SYN-ACK':  green('Opened'),
        'SYN':      yellow('Potentially Open'),
        'RSTACK':   red('Closed'),
        'FIN':      red('Connection Closed'),
        'RST':      red('Reset'),
        'Filtered': red('Filtered')
    }

    __slots__ = ('_target_ip', '_flags', '_target_ports', '_ports_to_sniff', '_packets', '_responses')

    def __init__(self, parser_manager:ArgParser) -> None:
        self._target_ip:str            = None
        self._args:dict                = None
        self._target_ports:dict        = None
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
            'decoy':  parser_manager.decoy,
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
        if   self._args['decoy']: self._target_ports = get_ports(self._args['decoy'])
        elif self._args['port']:  self._target_ports = get_ports(self._args['port'])
        elif self._args['all']:   self._target_ports = get_ports()
        else:                     self._target_ports = get_ports('common')

        if self._args['random']:
            random_list        = random.sample(list(self._target_ports.items()), len(self._target_ports))
            self._target_ports = dict(random_list)



    def _get_packets(self) -> None:
        if self._args['decoy']:
            self._get_decoy_and_real_packets()
        else:
            self._packets, self._ports_to_sniff = Packet()._get_tcp_packets(self._target_ip, self._target_ports)



    def _get_decoy_and_real_packets(self) -> None:
        decoy_ips     = self._generate_random_ip_in_subnet()
        decoy_packets = Packet()._get_decoy_tcp_packets(self._target_ip, self._target_ports, decoy_ips)
        packet, port  = Packet()._get_tcp_packets(self._target_ip, self._target_ports)
        pkt_number    = len(decoy_packets)
        real_ip_index = random.randint(pkt_number // 2, pkt_number - 1)
        decoy_packets.insert(packet, real_ip_index)
        self._packets        = decoy_packets
        self._ports_to_sniff = port



    def _generate_random_ip_in_subnet(self, count = random.randint(4, 6)) -> list[str]:
        ip_range   = get_ip_range()
        random_ips = random.sample(ip_range, count)
        return [str(ip) for ip in random_ips]



    def _send_and_receive(self) -> None:
        with Sniffer('IP', self._ports_to_sniff) as sniffer:
            self._send_packets()
            time.sleep(3)
            return sniffer._get_result()



    def _send_packets(self) -> None:
        delay_list = self._get_delay_time_list()
        index      = 1
        for delay, packet, port in zip(delay_list, self._packets, self._target_ports.values()):
            time.sleep(delay)
            send_layer_3_packet(packet, self._target_ip, port)
            sys.stdout.write(f'\rPacket sent: {index}/{len(self._packets)}')
            sys.stdout.flush()
            index += 1
        print('\n')



    def _get_delay_time_list(self) -> list[int]:
        if self._args['delay'] is False:
            return [0 for _ in range(len(self._packets))]
        elif self._args['delay'] is True or self._args['decoy']:
            return [0] + [random.uniform(1, 3) for _ in range(len(self._packets) - 1)]

        values = [float(value) for value in self._args['delay'].split('-')]
        if len(values) > 1:
            return [0] + [random.uniform(values[0], values[1]) for _ in range(len(self._packets) - 1)]
        return [0] + [values[0] for _ in range(len(self._packets) - 1)]



    def _display_result(self) -> None:
        for pkt_info in self._responses:
            flags       = pkt_info['flags']
            status      = self.STATUS.get(flags)
            port        = pkt_info['port']
            description = self._target_ports[port]
            if flags == 'SYN-ACK' or self._args['show']:
                print(f'Status: {status:>17} -> {port:>5} - {description}')
