# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import sys
from config.arg_parser   import ArgParser_Manager
from core.port_scanner   import Port_Scanner
from core.banner_grabber import Banner_Grabber
from core.network_mapper import Network_Mapper
from models.data         import Data


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
        self._data.command_name = sys.argv[1]
        self._data.arguments    = sys.argv[2:] if len(sys.argv) > 2 else list()


    def _handle_user(self) -> None:
        try:   self._verify_if_the_command_exists()
        except KeyboardInterrupt:  sys.exit()
        except IndexError:         print('Missing command name')
        except Exception as error: print(f'ERROR: {error}')
    

    def _verify_if_the_command_exists(self) -> None:
        if    self._data.command_name in self._commands:   self._validate_arguments()
        elif  self._data.command_name in ('--help', '-h'): self._display_description(self._commands)
        else: print(f'Unknown command: {self._data.command_name}')


    def _validate_arguments(self) -> None:
        if self._data.command_name!= 'netmap':
            with ArgParser_Manager(self._data): ...
        self._run_command()


    def _run_command(self) -> None:
        strategy_class:type = self._commands.get(self._data.command_name)
        with strategy_class(self._data) as strategy:
            strategy.execute()


    @staticmethod
    def _display_description(commands:dict) -> None:
        print('> Repository: https://github.com/olivercalazans/netexplorer\n'
              '> NetXplorer CLI is a tool for network exploration\n'
              'Available commands:')
        for name, class_name in commands.items():
            command:str   = class_name.__name__.replace('_', ' ')
            separetor:str = (10 - len(name)) * '.'
            print(f'{name}{separetor}: {command}')



if __name__ == '__main__':
    with Main() as xplorer:
        xplorer._handle_user()
