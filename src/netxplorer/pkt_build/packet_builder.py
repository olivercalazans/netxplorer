# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


from header_ip        import IP
from header_icmp      import ICMP
from header_tcp       import TCP
from header_udp       import UDP
from utils.type_hints import Raw_Packet


class Packet_Builder(IP, ICMP, TCP, UDP):

    @staticmethod
    def get_icmp_packet() -> Raw_Packet:
        return super().create_icmp_header()
    

    @staticmethod
    def create_tcp_header(dst_ip:int, src_port:str, dst_port:int) -> Raw_Packet:
        ip_header:bytes  = super().create_ip_header(dst_ip)
        tcp_header:bytes = super().create_tcp_header(dst_ip, src_port, dst_port)
        return ip_header + tcp_header
