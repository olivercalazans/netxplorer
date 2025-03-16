# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket, struct, random
from network    import get_ip_address
from type_hints import Raw_Packet


class Packet:

    PROTOCOLS = {
        'TCP': socket.IPPROTO_TCP,
        'UDP': socket.IPPROTO_ICMP,
    }

    __slots__ = ('_protocol', '_src_ip', '_src_port', '_dst_ip', '_dst_port')

    def __init__(self, protocol):
        self._protocol:int = self.PROTOCOLS.get(protocol, None)
        self._src_ip:str   = get_ip_address()
        self._src_port:int = None
        self._dst_ip:str   = None
        self._dst_port:int = None


    def create_tcp_packet(self, dst_ip:str, dst_ports:list[int]) -> tuple[list[Raw_Packet], list[int]]:
        packets = list()
        ports   = list()
        for port in dst_ports:
            self._set_packet_information(dst_ip, port)
            ip_header  = self._IP()
            tcp_header = self._TCP()
            packets.append(Raw_Packet(ip_header + tcp_header))
            ports.append(self._src_port)
        return packets, ports


    def _set_packet_information(self, dst_ip:str, dst_port:int) -> None:
        self._dst_ip   = dst_ip
        self._dst_port = dst_port
        self._src_port = random.randint(10000, 65535)


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