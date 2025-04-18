# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket
import fcntl
import struct
import re
import subprocess
import ipaddress


def get_default_iface() -> str:
    result = subprocess.run("ip route | awk '/default/ {print $5}'", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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



def get_ip_range() -> ipaddress.IPv4Address:
    ip_range = ipaddress.IPv4Network(f'{get_my_ip_address()}/{get_subnet_mask()}', strict=False)
    ip_range = [str(ip) for ip in ip_range.hosts()]
    ip_range.remove(get_my_ip_address())
    return ip_range



def get_host_name(ip:str) -> str:
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname[:-4] if hostname[-4:] == '.lan' else hostname
    except: return 'Unknown'



def get_ports(port_type='all') -> dict:
    match port_type:
        case 'common':   return get_common_ports()
        case 'uncommon': return get_uncommon_ports()
        case 'all':      return {**get_common_ports(), **get_uncommon_ports()}
        case _:          return get_specific_ports(port_type)



def get_specific_ports(string:str) -> dict:
    ALL_PORTS = {**get_common_ports(), **get_uncommon_ports()}
    parts     = re.split(r',', string)
    result    = list()

    for part in parts:
        if '-' in part:
            start, end = map(int, part.split('-'))
            if start >= end: raise ValueError(f'Invalid range: {start}-{end}')
            result.extend(range(start, end + 1))
        else:
            result.append(int(part))

    return {port: ALL_PORTS.get(port, 'Ephemeral Port / Dynamic Port') for port in result}



def get_common_ports() -> dict:
    return {
        20   : 'FTP - File Transfer Protocol (Data Transfer)',  
        21   : 'FTP - File Transfer Protocol (Command)',  
        22   : 'SSH - Secure Shell',  
        23   : 'Telnet',  
        25   : 'SMTP - Simple Mail Transfer Protocol',  
        53   : 'DNS - Domain Name System',  
        67   : 'DHCP - Dynamic Host Configuration Protocol (Server)',  
        68   : 'DHCP - Dynamic Host Configuration Protocol (Client)',  
        80   : 'HTTP - HyperText Transfer Protocol',  
        110  : 'POP3 - Post Office Protocol version 3',  
        143  : 'IMAP - Internet Message Access Protocol',  
        161  : 'SNMP - Simple Network Management Protocol',  
        443  : 'HTTPS - HTTP Protocol over TLS/SSL',  
        445  : 'SMB - Server Message Block',  
        587  : 'SMTP - Submission',  
        993  : 'IMAPS - IMAP over SSL',  
        995  : 'POP3S - POP3 over SSL',  
        3306 : 'MySQL/MariaDB',  
        3389 : 'RDP - Remote Desktop Protocol',  
        5432 : 'PostgreSQL',  
        5900 : 'VNC - Virtual Network Computing',  
        8080 : 'HTTP Alternative - Jakarta Tomcat',  
        8443 : 'HTTPS Alternative - Tomcat SSL',  
        8888 : 'HTTP Alternative',  
        11211: 'Memcached',  
        27017: 'MongoDB'
    }



def get_uncommon_ports() -> dict:
    return {
        69   : 'TFTP - Trivial File Transfer Protocol',  
        179  : 'BGP - Border Gateway Protocol',  
        194  : 'IRC - Internet Relay Chat',  
        465  : 'SMTPS - SMTP Secure (SSL)',  
        514  : 'Syslog - System Logging Protocol',  
        531  : 'RPC - Remote Procedure Call',  
        543  : 'Klogin - Kerberos Login',  
        550  : 'Kshell - Kerberos Shell',  
        631  : 'IPP - Internet Printing Protocol',  
        636  : 'LDAPS - Lightweight Directory Access Protocol over SSL',  
        1080 : 'SOCKS Proxy',  
        1433 : 'Microsoft SQL Server',  
        1434 : 'Microsoft SQL Server Resolution',  
        1500 : 'Radmin - Remote Administrator',  
        1521 : 'Oracle DB - Oracle Database Listener',  
        1723 : 'PPTP - Point to Point Tunneling Protocol',  
        1883 : 'MQTT - Message Queuing Telemetry Transport',  
        2049 : 'NFS - Network File System',  
        2181 : 'Zookeeper',  
        3690 : 'SVN - Subversion',  
        3372 : 'NAT-T - Network Address Translation Traversal (IPsec)',  
        4500 : 'NAT-T - Network Address Translation Traversal (IPsec)',  
        5000 : 'UPnP - Universal Plug and Play',  
        5001 : 'Synology NAS',  
        5800 : 'VNC - Virtual Network Computing',  
        6379 : 'Redis',  
        7070 : 'RealServer',  
        7777 : 'IIS - Microsoft Internet Information Services',  
        7778 : 'IIS - Microsoft Internet Information Services',  
        8000 : 'HTTP Alternate',  
        10000: 'Webmin',  
        20000: 'Webmin',  
        50000: 'SAP',  
        52000: 'Apple Remote Desktop',    
    }
