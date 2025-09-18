from typing             import Callable
from packet.layers.ip   import IP
from packet.layers.icmp import ICMP
from packet.layers.tcp  import TCP
from packet.layers.udp  import UDP
from utils.type_hints   import Raw_Packet


class Packet_Builder():

    @classmethod
    def build_packet(cls, protocol:str, *args) -> Raw_Packet:
        protocol_method:Callable = cls.PROTOCOLS.get(protocol)
        return protocol_method(protocol, *args)
    
    

    @staticmethod
    def _get_icmp_packet(_) -> Raw_Packet:
        return ICMP.create_icmp_header()

    

    @staticmethod
    def _get_tcp_ip_packet(protocol:str, dst_ip:int, dst_port:int) -> Raw_Packet:
        ip_header:bytes  = IP.create_ip_header(dst_ip, protocol)
        tcp_header:bytes = TCP.create_tcp_header(dst_ip, dst_port)
        return ip_header + tcp_header
    


    @staticmethod
    def _get_udp_ip_packet(protocol:str, dst_ip:str, dst_port:int) -> Raw_Packet:
        ip_header:bytes  = IP.create_ip_header(dst_ip, protocol)
        udp_header:bytes = UDP.create_udp_header(dst_ip, dst_port)
        return ip_header + udp_header



    PROTOCOLS:dict = {
        'ICMP': _get_icmp_packet,
        'TCP':  _get_tcp_ip_packet,
        'UDP':  _get_udp_ip_packet
    }