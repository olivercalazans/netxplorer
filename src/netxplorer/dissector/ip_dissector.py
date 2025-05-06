# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import struct
import socket


class IP_Dissector:

    SOURCE_IP_STRUCT:struct.Struct  = struct.Struct('4s')


    @staticmethod
    def get_ip_header(cls, packet:memoryview) -> memoryview:
        return packet[14:34]
    

    @staticmethod
    def get_protocol(ip_header:memoryview) -> memoryview:
        return ip_header[9]
    

    @classmethod
    def get_source_ip(cls, ip_header:memoryview) -> str:
        raw_bytes:bytes = cls.SOURCE_IP_STRUCT.unpack(ip_header[12:16])[0]
        return socket.inet_ntoa(raw_bytes)