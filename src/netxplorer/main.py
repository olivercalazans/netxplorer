# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import sys
from config.arg_parser   import ArgParser_Manager
from core.banner_grabber import Banner_Grabber
from core.network_mapper import Network_Mapper
from core.port_scanner   import Port_Scanner
from models.data         import Data


class Main:

    _data:Data     = Data()
    _commands:dict = {
        'pscan':  Port_Scanner,
        'banner': Banner_Grabber,
        'netmap': Network_Mapper
    }
    


    @classmethod
    def execute(cls) -> None:
        try:
            cls._get_data_from_system()
            cls._verify_if_the_command_exists()
            cls._validate_arguments()
            cls._run_command()
        except KeyboardInterrupt:  sys.exit()
        except IndexError:         print('Missing command name')
        except Exception as error: print(f'ERROR (Main): {error}')



    @classmethod
    def _get_data_from_system(cls) -> None:
        cls._data.command_name = sys.argv[1]
        cls._data.arguments    = sys.argv[2:] if len(sys.argv) > 2 else list()
    


    @classmethod
    def _verify_if_the_command_exists(cls) -> None:
        if cls._data.command_name not in cls._commands:
            print(f'Unknown command: {cls._data.command_name}')
        
        if cls._data.command_name in ('--help', '-h'):
            cls._display_description(cls._commands)



    @classmethod
    def _validate_arguments(cls) -> None:
        if cls._data.command_name!= 'netmap':
            with ArgParser_Manager(cls._data): ...



    @classmethod
    def _run_command(cls) -> None:
        strategy_class:type = cls._commands.get(cls._data.command_name)
        with strategy_class(cls._data) as strategy:
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
        
        sys.exit()
        





if __name__ == '__main__':
    Main().execute()
