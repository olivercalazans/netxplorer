# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import struct, socket
from type_hints import Raw_Packet


def dissect_tcp_ip_packet(packet:Raw_Packet) -> dict|None:
        try:
            ip_header = packet[14:34]
            ip_header = struct.unpack('!BBHHHBBH4s4s', ip_header)
            source_ip = socket.inet_ntoa(ip_header[8])
            print(f"IP Packet: Source: {source_ip}")              
        except Exception:
             return None