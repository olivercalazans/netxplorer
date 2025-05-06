# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import argparse
from models.data import Data


class ArgParser_Manager:

    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = object().__new__(cls)
        return cls._instance

    

    __slots__ = ('_data', '_parser', '_definitions')

    def __init__(self, data:Data):
        self._data:Data   = data
        self._parser      = argparse.ArgumentParser(description='Argument Manager')
        self._definitions = {
        'pscan':  self._validate_and_get_pscan_arguments,
        'banner': self._validate_and_get_bgrab_arguments,
    }


    def __enter__(self):
        command_arg_manager = self._definitions.get(self._data.command_name)
        command_arg_manager()
        return self


    def __exit__(self, exc_type, exc_value, traceback):
        self.__class__._instance = None
        return False
    


    def _validate_and_get_pscan_arguments(self) -> dict:
        self._parser.add_argument('host', type=str, help='Target IP/Hostname')
        self._parser.add_argument('-s', '--show', action='store_true', help='Display all statuses, both open and closed')
        self._parser.add_argument('-r', '--random', action='store_true', help='Use the ports in random order')
        self._parser.add_argument('-p', '--ports', type=str, help='Specify ports to scan')
        self._parser.add_argument('-a', '--all', action='store_true', help='Scan all ports')
        self._parser.add_argument('-d', '--delay', nargs='?', const=True, default=False, help='Add a delay between packet transmissions')
        self._parser = self._parser.parse_args(self._data.arguments)

        self._data.target_ip = self._parser.host
        self._data.arguments = {
            'show':   self._parser.show,
            'ports':  self._parser.ports,
            'all':    self._parser.all,
            'random': self._parser.random,
            'delay':  self._parser.delay,
        }



    def _validate_and_get_bgrab_arguments(self) -> None:
        PROTOCOLS = ['ftp', 'ssh', 'http', 'https']
        self._parser.add_argument('host', type=str, help='Target IP/Hostname')
        self._parser.add_argument('protocol', type=str, choices=PROTOCOLS, help='Protocol')
        self._parser.add_argument('-p', '--port', type=str, help='Specify a port to grab the banners')
        self._parser = self._parser.parse_args(self._data.arguments)

        self._data.target_ip = self._parser.host
        self._data.ports     = self._parser.port
        self._data.arguments = {'protocol': self._parser.protocol}