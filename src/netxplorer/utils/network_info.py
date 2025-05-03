# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket
import fcntl
import struct
import subprocess
import ipaddress
import random


def get_default_iface() -> str:
    result:subprocess.CompletedProcess[str] = subprocess.run(
        "ip route | awk '/default/ {print $5}'",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    return result.stdout.strip()



def temporary_socket(OP_CODE:int, INTERFACE=get_default_iface()) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        return socket.inet_ntoa(
            fcntl.ioctl(sock.fileno(), OP_CODE,
            struct.pack('256s', INTERFACE[:15].encode('utf-8'))
        )[20:24])



def get_my_ip_address() -> str|None:
    try:   return temporary_socket(0x8915)
    except Exception: return None



def get_subnet_mask() -> str|None:
    try:   return temporary_socket(0x891b)
    except Exception: return None



def get_ip_range() -> list[str]:
    my_ip_address:str              = get_my_ip_address()
    ip_range:ipaddress.IPv4Network = ipaddress.IPv4Network(f'{my_ip_address}/{get_subnet_mask()}', strict=False)
    ip_range:list[str]             = [str(ip) for ip in ip_range.hosts()]
    ip_range.remove(my_ip_address)
    return ip_range



def get_host_name(ip:str) -> str:
    try:
        hostname:str = socket.gethostbyaddr(ip)[0]
        return hostname[:-4] if hostname[-4:] == '.lan' else hostname
    except: return 'Unknown'



def get_random_ports(number:int) -> list[int]:
    return [random.randint(10000, 65535) for _ in range(number)]