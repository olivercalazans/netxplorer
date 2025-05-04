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



    def get_packets(self) -> list[dict]:
        self._stop_sniffing()
        print(len(self._responses))
        return self._responses



    def _create_sniffer(self) -> BPF_Configured_Socket:
        sniffer:socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sniffer.bind((get_default_iface(), 0))

        bpf_filter:BPF_Instruction = self._define_filter()
        
        for i in bpf_filter:print(i)

        filter_array:int           = (sock_filter * len(bpf_filter))()
        for i, (code, jt, jf, k) in enumerate(bpf_filter):
            filter_array[i] = sock_filter(code, jt, jf, k)

        prog:sock_fprog = sock_fprog(len(bpf_filter), filter_array)

        SO_ATTACH_FILTER:int = 26
        libc:ctypes.CDLL     = ctypes.cdll.LoadLibrary("libc.so.6")
        libc.setsockopt(sniffer.fileno(), socket.SOL_SOCKET, SO_ATTACH_FILTER, ctypes.byref(prog), ctypes.sizeof(prog))

        self._sniffer = sniffer





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