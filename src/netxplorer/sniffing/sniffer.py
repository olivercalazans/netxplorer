# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket
import ctypes
import threading
import select
from utils.network_info import get_default_iface
from utils.type_hints   import BPF_Instruction, BPF_Configured_Socket


class Sniffer:

    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = object().__new__(cls)
        return cls._instance

    

    __slots__ = ('_protocol', '_ports', '_sniffer', '_running', '_thread', '_responses')

    def __init__(self, protocol:str, ports:list=None) -> None:
        self._protocol:str                  = protocol
        self._ports:list[int]               = ports
        self._sniffer:BPF_Configured_Socket = None
        self._running:bool                  = True
        self._thread:threading.Thread       = None
        self._responses:list[dict]          = list()

    

    def __enter__(self):
        self._create_sniffer()
        self._start_sniffing()
        return self
    

    def __exit__(self, exc_type, exc_value, traceback):
        return False



    def _start_sniffing(self) -> None:
        self._thread = threading.Thread(target=self._sniff)
        self._thread.start()



    def _sniff(self):
        while self._running is True:
            readable, _, _= select.select([self._sniffer], [], [], 0.001)
            if readable:
                packet, _ = self._sniffer.recvfrom(65535)
                self._responses.append(packet)



    def _stop_sniffing(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join()



    def _get_packets(self) -> list[dict]:
        self._stop_sniffing()
        return self._responses



    def _create_sniffer(self) -> BPF_Configured_Socket:
        sniffer:socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sniffer.bind((get_default_iface(), 0))

        bpf_filter:BPF_Instruction = self._define_filter()

        filter_array:int           = (sock_filter * len(bpf_filter))()
        for i, (code, jt, jf, k) in enumerate(bpf_filter):
            filter_array[i] = sock_filter(code, jt, jf, k)

        prog:sock_fprog = sock_fprog(len(bpf_filter), filter_array)

        SO_ATTACH_FILTER:int = 26
        libc:ctypes.CDLL     = ctypes.cdll.LoadLibrary("libc.so.6")
        libc.setsockopt(sniffer.fileno(), socket.SOL_SOCKET, SO_ATTACH_FILTER, ctypes.byref(prog), ctypes.sizeof(prog))

        self._sniffer = sniffer
        


    BPF_MAP = {
        'Jump if EtherType':    lambda jt, jf, d: (0x28, jt, jf, 12),
        'Jump if IPv4':         lambda jt, jf, d: (0x15, jt, jf, 2048),
        'Load IPv4 header':     lambda jt, jf, d: (0x30, jt, jf, 23),
        'Jump if TCP':          lambda jt, jf, d: (0x15, jt, jf, 6),
        'Load dst port':        lambda jt, jf, d: (0x28, jt, jf, 36),
        'Jump if TCP dst port': lambda jt, jf, d: (0x15, jt, jf, d),
        'Jump if ICMP':         lambda jt, jf, d: (0x15, jt, jf, 1),
        'Load ICMP header':     lambda jt, jf, d: (0x30, jt, jf, 20),
        'Jump if Echo Reply':   lambda jt, jf, d: (0x15, jt, jf, 0),
        'Accept packet':        lambda jt, jf, d: (0x06, jt, jf, 0xFFFF),
        'Discard packet':       lambda jt, jf, d: (0x06, jt, jf, 0x0000),
    }



    @staticmethod
    def _get_parameter(type:str, true_jump:int, false_jump:int, dst_port:int=None) -> BPF_Instruction:
        parameter:tuple = Sniffer.BPF_MAP[type](true_jump, false_jump, dst_port)
        return parameter



    def _define_filter(self) -> BPF_Instruction:
        filter:list = [self._get_parameter('Jump if EtherType', 0, 0)]
        filter:list = filter + self._get_protocol_parameters()
        filter:list = filter + [
            self._get_parameter('Accept packet',  0, 0),
            self._get_parameter('Discard packet', 0, 0)
        ]
        return filter



    def _get_protocol_parameters(self) -> list[tuple]:
        match self._protocol:
            case 'TCP':      return self._get_tcp_parameters()
            case 'ICMP':     return self._get_icmp_parameters()
            case 'TCP-ICMP': return self._get_tcp_icmp_parameters()



    def _get_tcp_parameters(self, other_jumps:int=0) -> BPF_Instruction:
        port_jumps:BPF_Instruction = self._create_tcp_port_parameters(other_jumps)
        num:int         = len(port_jumps)
        parameters:list = [
            self._get_parameter('Jump if IPv4',     0, num + 4 + other_jumps),
            self._get_parameter('Load IPv4 header', 0, 0),
            self._get_parameter('Jump if TCP',      0, num + 2),
            self._get_parameter('Load dst port',    0, 0)
        ]
        return parameters + port_jumps

    

    def _create_tcp_port_parameters(self, other_jumps:int) -> BPF_Instruction:
        port_parameters:list = [
            self._get_parameter('Jump if TCP dst port', other_jumps, 1 + other_jumps, self._ports[0])
        ]
        
        for i, port in enumerate(self._ports[1:], start=1):
            new_parameter:tuple = self._get_parameter('Jump if TCP dst port', i + other_jumps, 0, port)
            port_parameters.insert(0, new_parameter)
        
        return port_parameters



    @staticmethod
    def _get_icmp_parameters() -> BPF_Instruction:
        return [
            Sniffer._get_parameter('Jump if IPv4',       0, 5),
            Sniffer._get_parameter('Load IPv4 header',   0, 0),
            Sniffer._get_parameter('Jump if ICMP',       0, 3),
            Sniffer._get_parameter('Load ICMP header',   0, 0),
            Sniffer._get_parameter('Jump if Echo Reply', 0, 1)
        ]
    


    def _get_tcp_icmp_parameters(self) -> BPF_Instruction:
        icmp_parameters:list = self._get_icmp_parameters()[-3:]
        tcp_parameters:list  = self._get_tcp_parameters(len(icmp_parameters))
        return tcp_parameters + icmp_parameters





# Define a BPF filter structure
class sock_filter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort), #...: Operation Code
        ("jt", ctypes.c_ubyte), #......: Jump if True
        ("jf", ctypes.c_ubyte), #......: Jump if False
        ("k", ctypes.c_uint), #........: Byte offset position | Value
    ]




# Defines the structure of the complete BPF filter
class sock_fprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.POINTER(sock_filter)),
    ]