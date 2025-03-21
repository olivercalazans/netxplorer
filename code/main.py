# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import sys
from arg_parser import validate_and_get_flags
from port_scan  import Port_Scanner
from bgrab      import Banner_Grabber
#from netmap     import Network_Mapper
from display    import *


class Main:

    COMMAND_DICT = {
        'pscan':  Port_Scanner,
        'banner': Banner_Grabber,
#        'netmap': Network_Mapper
    }

    __slots__ = ('_command', '_arguments')

    def __init__(self) -> None:
        self._command:str    = None
        self._arguments:list = None


    def _handle_user(self) -> None:
        try:   self._validate_input()
        except KeyboardInterrupt:  sys.exit()
        except IndexError:         print(yellow("Missing command name"))
        except Exception as error: print(unexpected_error(error))

    
    def _validate_input(self) -> None:
        self._command   = sys.argv[1]
        self._arguments = sys.argv[2:] if len(sys.argv) > 2 else list()
        self._verify_if_the_command_exists()


    def _verify_if_the_command_exists(self) -> None:
        if    self._command in self.COMMAND_DICT: self._validate_arguments()
        elif  self._command in ('--help', '-h'):  self._display_description()
        else: print(f'{yellow("Unknown command")} "{self._command}"')


    def _validate_arguments(self) -> None:
        arguments = validate_and_get_flags(self._command, self._arguments)
        self._run_command(arguments)


    def _run_command(self, arguments:dict) -> None:
        strategy_class = self.COMMAND_DICT.get(self._command)
        with strategy_class(arguments) as strategy:
            strategy._execute()


    @staticmethod
    def _display_description() -> None:
        print('Repository: https://github.com/olivercalazans/netexplorer\n'
              'NetXplorer CLI is a tool for network exploration\n'
              'Available commands:\n'
              f'{green("pscan")}....: Portscaning\n'
              f'{green("banner")}...: Banner Grabbing\n'
              f'{green("netmap")}...: Network Mapping\n'
              )



if __name__ == '__main__':
    user = Main()
    user._handle_user()
