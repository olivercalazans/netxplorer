# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket
from random             import randint
from struct             import Struct
from utils.network_info import get_my_ip_address


class IP:

    _IP_STRUCT:Struct = Struct('!BBHHHBBH4s4s')
    _MY_IP:str        = socket.inet_aton(get_my_ip_address())

    @classmethod
    def create_ip_header(cls, dst_ip:str) -> bytes:
        return cls._IP_STRUCT.pack(
            (4 << 4) + 5, #..............: IP version and IHL (Internet Header Length)
            0, #.........................: TOS (Type of Service)
            40, #........................: Total length
            randint(10000, 65535), #.....: IP ID
            0, #.........................: Flags and Fragment offset
            64, #........................: TLL (Time to Live)
            socket.IPPROTO_TCP, #........: Protocol
            0, #.........................: Checksum (Will be populated by the kernel)
            cls._MY_IP, #................: Source IP
            socket.inet_aton(dst_ip) #...: Destiny IP
        )