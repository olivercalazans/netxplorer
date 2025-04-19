# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import sys
from arg_parser import ArgParser_Manager
from data_class import Data
from port_scan  import Port_Scanner
from bgrab      import Banner_Grabber
from netmap     import Network_Mapper


class Main:

    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = object().__new__(cls)
        return cls._instance


    __slots__ = ('_data', '_commands')

    def __init__(self) -> None:
        self._data:Data     = Data()
        self._commands:dict = {
        'pscan':  Port_Scanner,
        'banner': Banner_Grabber,
        'netmap': Network_Mapper
    }

    
    def __enter__(self):
        self._get_data_from_system()
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        return False
    

    def _get_data_from_system(self) -> None:
        self._data._command_name = sys.argv[1]
        self._data._arguments    = sys.argv[2:] if len(sys.argv) > 2 else list()


    def _handle_user(self) -> None:
        try:   self._verify_if_the_command_exists()
        except KeyboardInterrupt:  sys.exit()
        except IndexError:         print('Missing command name')
        except Exception as error: print(f'ERROR: {error}')
    

    def _verify_if_the_command_exists(self) -> None:
        if    self._data._command_name in self._commands:   self._validate_arguments()
        elif  self._data._command_name in ('--help', '-h'): self._display_description()
        else: print(f'Unknown command: {self._data._command_name}')


    def _validate_arguments(self) -> None:
        if self._data._command_name!= 'netmap':
            with ArgParser_Manager(self._data): ...
        self._run_command()


    def _run_command(self) -> None:
        strategy_class = self._commands.get(self._data._command_name)
        with strategy_class(self._data) as strategy:
            strategy._execute()


    @staticmethod
    def _display_description() -> None:
        print('Repository: https://github.com/olivercalazans/netexplorer\n'
              'NetXplorer CLI is a tool for network exploration\n'
              'Available commands:\n'
              f'pscan....: Portscaning\n'
              f'banner...: Banner Grabbing\n'
              f'netmap...: Network Mapping\n'
              )



if __name__ == '__main__':
    with Main() as xplorer:
        xplorer._handle_user()
