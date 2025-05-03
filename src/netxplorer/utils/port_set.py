# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import re


class Port_Set:

    @staticmethod
    def get_ports(port_type='all') -> dict:
        match port_type:
            case 'common':   return Port_Set._COMMON_TCP_PORTS
            case 'uncommon': return Port_Set._COMMON_TCP_PORTS
            case 'all':      return Port_Set._mix_tcp_ports()
            case _:          return Port_Set._get_specific_ports(port_type)


    @staticmethod
    def _mix_tcp_ports() -> dict:
        return {**Port_Set._COMMON_TCP_PORTS, **Port_Set._UNCOMMON_TCP_PORTS}


    @staticmethod
    def _get_specific_ports(string:str) -> dict:
        ALL_PORTS:dict = Port_Set._mix_tcp_ports()
        parts:list     = re.split(r',', string)
        result:list    = list()

        for part in parts:
            if '-' in part:
                start, end = map(int, part.split('-'))
                if start >= end: raise ValueError(f'Invalid range: {start}-{end}')
                result.extend(range(start, end + 1))
            else:
                result.append(int(part))

        return {port: ALL_PORTS.get(port, 'Ephemeral Port / Dynamic Port') for port in result}



    _COMMON_TCP_PORTS = {
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



    _UNCOMMON_TCP_PORTS = {
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



    _COMMON_UDP_PORTS = {
        53    : 'DNS - Domain Name System (queries)',
        67    : 'DHCP - Dynamic Host Configuration Protocol (Server)',
        68    : 'DHCP - Dynamic Host Configuration Protocol (Client)',
        69    : 'TFTP - Trivial File Transfer Protocol',
        123   : 'NTP - Network Time Protocol',
        137   : 'NetBIOS Name Service',
        138   : 'NetBIOS Datagram Service',
        161   : 'SNMP - Simple Network Management Protocol',
        162   : 'SNMP Trap - Alert Receiver',
        500   : 'IKE - Internet Key Exchange (IPsec VPN)',
        514   : 'Syslog - System Logging Protocol (UDP variant)',
        520   : 'RIP - Routing Information Protocol',
        623   : 'IPMI - Remote Management Control Protocol',
        1645  : 'RADIUS - Authentication (legacy)',
        1646  : 'RADIUS - Accounting (legacy)',
        1701  : 'L2TP - Layer 2 Tunneling Protocol',
        1812  : 'RADIUS - Authentication',
        1813  : 'RADIUS - Accounting',
        1900  : 'SSDP - Simple Service Discovery Protocol (UPnP)',
        2049  : 'NFS - Network File System',
        5353  : 'mDNS - Multicast DNS (Bonjour/Avahi)',
        33434 : 'Traceroute - Linux (start port)',
    }
