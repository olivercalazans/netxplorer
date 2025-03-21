# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import argparse


PROTOCOLS   = ['ftp', 'ssh', 'http', 'https']
DEFINITIONS = {
    'pscan': [
        ('arg',   'host', 'Target IP/Hostname'),
        ('bool',  '-s', '--show',   'Display all statuses, both open and closed'),
        ('bool',  '-r', '--random', 'Use the ports in random order'),
        ('value', '-p', '--port',   str, 'Specify a port to scan'),
        ('bool',  '-a', '--all',    'Scan all ports'),
        ('opt',   '-d', '--delay',  'Add a delay between packet transmissions'),
        ],

    'banner': [
        ('arg',    'host',     'Target IP/Hostname'),
        ('choice', 'protocol', PROTOCOLS, 'Protocol'),
        ('value',  '-p', '--port', str, 'Specify a port to grab the banners')
        ],

    'netmap': [
        ('bool', '-p', '--ping', 'Use ping instead of an ARP packet')
        ]
}
    
# Method that will be called by the class
def parse(command:str, arguments:list) -> argparse.Namespace:
    parser      = argparse.ArgumentParser(description="Argument Manager")
    definitions = DEFINITIONS.get(command)
    create_arguments(parser, definitions)
    return parser.parse_args(arguments)


def create_arguments(parser:argparse.ArgumentParser, definitions:list[tuple]) -> None:
    for arg in definitions:
        match arg[0]:
            case 'bool':  parser.add_argument(arg[1], arg[2], action="store_true", help=arg[3])
            case 'value': parser.add_argument(arg[1], arg[2], type=arg[3], help=arg[4])
            case 'opt':   parser.add_argument(arg[1], arg[2], nargs='?', const=True, default=False, help=arg[3])
            case 'arg':   parser.add_argument(arg[1], type=str, help=arg[2])
            case _:       parser.add_argument(arg[1], type=str, choices=arg[2], help=arg[3])