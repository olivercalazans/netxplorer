# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


from pkt_build.header_ip   import IP
from pkt_build.header_icmp import ICMP
from pkt_build.header_tcp  import TCP
from pkt_build.header_udp  import UDP
from utils.type_hints      import Raw_Packet


class Packet_Builder():

    @staticmethod
    def get_icmp_packet() -> Raw_Packet:
        return ICMP.create_icmp_header()
    

    @staticmethod
    def get_tcp_ip_packet(dst_ip:int, dst_port:int) -> Raw_Packet:
        ip_header:bytes  = IP.create_ip_header(dst_ip)
        tcp_header:bytes = TCP.create_tcp_header(dst_ip, dst_port)
        return ip_header + tcp_header
