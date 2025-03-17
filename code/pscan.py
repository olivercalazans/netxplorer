# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import random, socket
from arg_parser   import Argument_Manager as ArgParser
from pscan_normal import Normal_Scan
from pscan_decoy  import Decoy
from network      import get_ports
from pkt_builder  import Packet
from type_hints   import Raw_Packet
from display      import *


class Port_Scanner:

    STATUS = {
        'SYN-ACK':  green('Opened'),
        'SYN':      yellow('Potentially Open'),
        'RSTACK':   red('Closed'),
        'FIN':      red('Connection Closed'),
        'RST':      red('Reset'),
        'Filtered': red('Filtered')
    }


    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        return False    


    __slots__ = ('_target_ip', '_flags', '_ports', '_responses')

    def __init__(self, parser_manager:ArgParser) -> None:
        self._target_ip:str              = None
        self._flags:dict                 = None
        self._ports:dict                 = None
        self._responses:list[Raw_Packet] = None
        self._get_argument_and_flags(parser_manager)


    def _get_argument_and_flags(self, parser_manager:ArgParser) -> None:
        self._target_ip  = socket.gethostbyname(parser_manager.host)
        self._flags = {
            'show':   parser_manager.show,
            'port':   parser_manager.port,
            'all':    parser_manager.all,
            'random': parser_manager.random,
            'delay':  parser_manager.delay,
            'decoy':  parser_manager.decoy,
        }


    def _execute(self) -> None:
        try:
            self._get_result_by_transmission_method()
            self._display_result()
        except KeyboardInterrupt:   print(f'\n{red("Process stopped")}')
        except ValueError as error: print(f'{yellow("Error")}: {error}')
        except Exception as error:  print(unexpected_error(error))


    def _get_result_by_transmission_method(self) -> list:
        if self._flags['decoy']: self._perform_decoy_scan()
        else:                    self._perform_normal_scan()

    
    def _perform_normal_scan(self) -> None:
        self._prepare_ports()
        with Normal_Scan(self._target_ip, list(self._ports.keys()), self._flags) as SCAN:
            self._responses = SCAN._perform_normal_methods()


    def _perform_decoy_scan(self) -> None:
        self._prepare_ports()
        with Decoy(self._target_ip, list(self._ports.keys())) as DECOY:
            self._responses     = DECOY._perform_decoy_methods()
            self._flags['show'] = True


    def _prepare_ports(self) -> None:
        if   self._flags['decoy']: self._ports = get_ports(self._flags['decoy'])
        elif self._flags['port']:  self._ports = get_ports(self._flags['port'])
        elif self._flags['all']:   self._ports = get_ports()
        else:                      self._ports = get_ports('common')

        if self._flags['random']:
            random_list = random.sample(list(self._ports.items()), len(self._ports))
            self._ports = dict(random_list)


    def _display_result(self) -> None:
        for pkt_info in self._responses:
            flag        = pkt_info['flags']
            status      = self.STATUS.get(flag)
            port        = pkt_info['port']
            description = self._ports[port]
            if flag == 'SYN-ACK' or self._flags['show']:
                print(f'Status: {status:>17} -> {port:>5} - {description}')