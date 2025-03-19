# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket, struct, random
from net_info   import get_my_ip_address
from type_hints import Raw_Packet


class Packet:

    __slots__ = ('_src_ip', '_src_port', '_dst_ip', '_dst_port', '_protocol')

    def __init__(self):
        self._src_ip:str   = get_my_ip_address()
        self._src_port:int = None
        self._dst_ip:str   = None
        self._dst_port:int = None
        self._protocol:int = None


    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        return False


    def _get_tcp_packets(self, dst_ip:str, dst_ports:list[int]) -> tuple[list[Raw_Packet], list[int]]:
        self._protocol = socket.IPPROTO_TCP
        packets        = list()
        ports          = list()
        self._dst_ip   = dst_ip
        for port in dst_ports:
            self._dst_port = port
            self._src_port = random.randint(10000, 65535)
            packets.append(self._create_tcp_packet())
            ports.append(self._src_port)
        return packets, ports


    def _create_tcp_packet(self) -> Raw_Packet:
        ip_header  = self._IP()
        tcp_header = self._TCP()
        return Raw_Packet(ip_header + tcp_header)



    # LAYERS -----------------------------------------------------------------------------------------------------

    def _IP(self) -> bytes:
        return struct.pack('!BBHHHBBH4s4s',
                           (4 << 4) + 5, #.....................: IP version and IHL (Internet Header Length)
                           0, #................................: TOS (Type of Service)
                           40, #...............................: Total length
                           random.randint(10000, 65535), #.....: IP ID
                           0, #................................: Flags and Fragment offset
                           64, #...............................: TLL (Time to Live)
                           self._protocol, #...................: Protocol
                           0, #................................: Checksum (Will be populated by the kernel)
                           socket.inet_aton(self._src_ip), #...: Source IP
                           socket.inet_aton(self._dst_ip) #....: Destiny IP
                           )



    def _TCP(self) -> bytes:
        tcp_header = struct.pack('!HHLLBBHHH',
                                 self._src_port, #.......: Source port
                                 self._dst_port, #.......: Destiny port
                                 0, #....................: Sequence
                                 0, #....................: Acknowledge
                                 (5 << 4), #.............: Data offset = 5 words (20 bytes), no options
                                 (True << 1), #..........: Flags
                                 socket.htons(5840), #...: Window size
                                 0, #....................: Checksum (will be calculated)
                                 0 #.....................: Urgent pointer
                                 )
        pseudo_hdr   = self._pseudo_header(len(tcp_header))
        tcp_checksum = self._checksum(pseudo_hdr + tcp_header)

        return struct.pack('!HHLLBBHHH', self._src_port, self._dst_port, 0, 0, (5 << 4),
                           (True << 1), socket.htons(5840), tcp_checksum, 0)



    def _pseudo_header(self, tcp_length:int) -> bytes:
        return struct.pack('!4s4sBBH',
                           socket.inet_aton(self._src_ip), #...: Source IP
                           socket.inet_aton(self._dst_ip), #...: Destiny IP
                           0, #................................: Reserved
                           self._protocol, #...................: Protocol
                           tcp_length #........................: TCP header length
                           )


    @staticmethod
    def _checksum(headers) -> int:
        s = 0
        for i in range(0, len(headers), 2):
            w = (headers[i] << 8) + (headers[i+1] if i+1 < len(headers) else 0)
            s += w
        s = (s >> 16) + (s & 0xffff)
        s += (s >> 16)
        return ~s & 0xffff