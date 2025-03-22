# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import argparse


# PORTSCANNER ============================================================================================
def pscan_definitions(parser:argparse.ArgumentParser, arguments:list) -> dict:
    parser.add_argument('host', type=str, help='Target IP/Hostname')
    parser.add_argument('-s', '--show', action='store_true', help='Display all statuses, both open and closed')
    parser.add_argument('-r', '--random', action='store_true', help='Use the ports in random order')
    parser.add_argument('-p', '--port', type=str, help='Specify a port to scan')
    parser.add_argument('-a', '--all', action='store_true', help='Scan all ports')
    parser.add_argument('-d', '--delay', nargs='?', const=True, default=False, help='Add a delay between packet transmissions')
    parser = parser.parse_args(arguments)
    return {
        'host':   parser.host,
        'show':   parser.show,
        'port':   parser.port,
        'all':    parser.all,
        'random': parser.random,
        'delay':  parser.delay,
    }



# BANNER GRABBER ========================================================================================
def bgrab_definitions(parser:argparse.ArgumentParser, arguments:list) -> dict:
    PROTOCOLS = ['ftp', 'ssh', 'http', 'https']
    parser.add_argument('host', type=str, help='Target IP/Hostname')
    parser.add_argument('protocol', type=str, choices=PROTOCOLS, help='Protocol')
    parser.add_argument('-p', '--port', type=str, help='Specify a port to grab the banners')
    parser = parser.parse_args(arguments)
    return {
        'host':     parser.host,
        'protocol': parser.protocol,
        'port':     parser.port
    }


# NETWORK MAPPER ========================================================================================
def netmap_definitions(parser:argparse.ArgumentParser, arguments:list) -> dict:
    parser.add_argument('-p', '--port', action='store_true', help='Use ping instead of an ARP packet')
    parser = parser.parse_args(arguments)
    return{
        'port': parser.port
    }



# ===============================================================================================================================

DEFINITIONS = {
    'pscan':  pscan_definitions,
    'banner': bgrab_definitions,
    'netmap': netmap_definitions,
}


# Method that will be called by the class
def validate_and_get_flags(command:str, arguments:list) -> argparse.Namespace:
    parser       = argparse.ArgumentParser(description='Argument Manager')
    command_args = DEFINITIONS.get(command)
    return command_args(parser, arguments)