# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket
from utils.type_hints import Raw_Packet

def send_layer_3_packet(packet:Raw_Packet, target_ip:str, port:int) -> None:
    sock:socket.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sock.sendto(packet, (target_ip, port))


def send_ping(packet:Raw_Packet, ip:str) -> None:
    sock:socket.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.sendto(packet, (ip, 1))
    sock.close()