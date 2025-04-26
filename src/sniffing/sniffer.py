# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket
import ctypes
import threading
import select
from net_info   import get_default_iface
from type_hints import BPF_Instruction, BPF_Configured_Socket


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
        sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sniffer.bind((get_default_iface(), 0))

        bpf_filter   = self._define_filter()
        filter_array = (sock_filter * len(bpf_filter))()
        for i, (code, jt, jf, k) in enumerate(bpf_filter):
            filter_array[i] = sock_filter(code, jt, jf, k)

        prog = sock_fprog(len(bpf_filter), filter_array)

        SO_ATTACH_FILTER = 26
        libc = ctypes.cdll.LoadLibrary("libc.so.6")
        libc.setsockopt(sniffer.fileno(), socket.SOL_SOCKET, SO_ATTACH_FILTER, ctypes.byref(prog), ctypes.sizeof(prog))

        self._sniffer = sniffer



    def _define_filter(self) -> BPF_Instruction:
        filter  = [(0x28, 0, 0, 12)] #.......: Load EtherType (offset 12)
        filter += self._get_parameters() #...: Specific parameters
        filter += [(0x06, 0, 0, 0xFFFF), #...: Accept packet
                   (0x06, 0, 0, 0x0000)] #...: Discard packet
        return filter
    


    def _get_parameters(self) -> list[tuple]:
        match self._protocol:
            case 'TCP':  return self._get_tcp_filter_parameters()
            case 'ICMP': return self._get_icmp_parameters()



    def _get_tcp_filter_parameters(self) -> BPF_Instruction:
        port_jumps = self._create_port_jumps()
        num        = len(port_jumps)
        parameters = [
            (0x15, 0, num + 4, 2048), #...: Jump if EtherType != IPv4
            (0x30, 0, 0,       23), #.....: Load IP Protocol
            (0x15, 0, num + 2, 6), #......: Jump if Protocol != TCP
            (0x28, 0, 0,       36) #......: Load Destination Port
        ]
        return parameters + port_jumps



    def _create_port_jumps(self) -> BPF_Instruction:
        len_ports       = len(self._ports)
        port_parameters = list()
        for i, port in enumerate(self._ports):
            true_jump  = len_ports - (i+1)
            false_jump = 0 if i + 1 < len_ports else 1 
            port_parameters.append((0x15, true_jump, false_jump, port))
        return port_parameters



    @staticmethod
    def _get_icmp_parameters() -> BPF_Instruction:
        return [
            (0x15, 0, 5, 2048), #...: Jump if EtherType == IPv4
            (0x30, 0, 0, 23), #.....: Load IP Protocol
            (0x15, 0, 3, 1), #......: Jump if protocol != ICMP
            (0x30, 0, 0, 20), #.....: Load ICMP header
            (0x15, 0, 1, 0), #......: Jump if != Echo Reply
        ]


# Define a BPF filter structure
class sock_filter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint),
    ]




# Defines the structure of the complete BPF filter
class sock_fprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.POINTER(sock_filter)),
    ]