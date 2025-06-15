# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket
import ssl
from models.data import Data


class Banner_Grabber:

    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = object().__new__(cls)
        return cls._instance



    __slots__ = ('_data')

    def __init__(self, data:dict) -> None:
        self._data:Data = data



    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.__class__._instance = None
        return False



    def execute(self) -> None:
        try:   self._grab_banners_on_the_protocol()
        except KeyboardInterrupt:               print('Process stopped')
        except ConnectionRefusedError as error: print(f'Connection refused: {error}')
        except socket.timeout as error:         print(f'Timeout: {error}')
        except socket.error as error:           print(f'Socket error: {error}')
        except Exception as error:              print(f'ERROR: {error}')



    def _grab_banners_on_the_protocol(self) -> None:
        protocol = self._protocol_dictionary().get(self._data.arguments['protocol'])
        port     = self._data.arguments['port'] or protocol['port']
        protocol['func'](self._data.target_ip, port)



    @staticmethod
    def _protocol_dictionary() -> dict:
        return {
            'ftp':   {'func': ftp_banner_grabbing,   'port': 21},
            'ssh':   {'func': ssh_banner_grabbing,   'port': 22},
            'http':  {'func': http_banner_grabbing,  'port': 80},
            'https': {'func': https_banner_grabbing, 'port': 443}
        }




# FUNCTIONS ==================================================================================================

def ftp_banner_grabbing(host:str, port:int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect((host, port))

        banner = sock.recv(1024).decode('utf-8').strip()

        if banner: print(f'[+] FTP Banner de {host}:{port} -> {banner}')
        else:      print(f'[-] Nenhum banner recebido de {host}:{port}')



def ssh_banner_grabbing(host:str, port:int) -> None:
    with socket.create_connection((host, port), timeout=5) as sock:
        banner = sock.recv(1024).decode(errors="ignore")
        banner = banner.split(',')
        print(f'[+] SSH server banner')
        for line in banner:
            if not line == '': print(f'  - {line.strip()}')



def http_banner_grabbing(host:str, port:int) -> None:
    with socket.create_connection((host, port), timeout=5) as sock:
        request = f'HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'
        sock.send(request.encode())
        response = sock.recv(4096).decode(errors='ignore')

        print('[+] HTTP server response:')
        for line in response.split("\r\n"):
            if line == '': continue
            print(line)



def https_banner_grabbing(host:str, port:int) -> None:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:            
            cert = ssock.getpeercert()

            if cert:
                print(f'[+] {host} SSL Certificate:')
                for field, value in cert.items():
                    print(f'{field}: {value}')
            else:
                print('No SSL certificates returned')

            print('HTTP header (if present):')
            ssock.send(b'GET / HTTP/1.1\r\nHost: ' + host.encode() + b'\r\n\r\n')
            response = ssock.recv(1024)
            for line in response.decode(errors='ignore').split("\r\n"):
                if line == '': continue
                print(line)