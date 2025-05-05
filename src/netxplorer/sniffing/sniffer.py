# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket
import ctypes
import select
from threading import Thread, Lock
from sniffing.bpf_filter import BPF_Filter
from utils.network_info  import get_default_iface
from utils.type_hints    import BPF_Instruction, BPF_Configured_Socket


class Sniffer:

    _instance:"Sniffer" = None
    
    def __new__(cls, *args, **kwargs) -> None:
        if cls._instance is None:
            cls._instance = object().__new__(cls)
        return cls._instance

    

    __slots__ = ('_protocols', '_running', '_sniffers', '_lock', 'ports', '_responses')

    def __init__(self, protocols:str, tcp_ports:list=None, udp_ports=None) -> None:
        self._protocols:list = protocols.split('-')
        self._running:bool   = True
        self._sniffers:list  = []
        self._lock:Lock      = Lock()
        self._ports:dict     = {'TCP': tcp_ports, 'UDP': udp_ports}
        self._responses:dict = {}

    

    def __enter__(self):
        self._start_sniffers()
        return self
    

    def __exit__(self, exc_type, exc_value, traceback):
        return False



    def _start_sniffers(self) -> None:
        for protocol in self._protocols:
            sniffer:Thread = Thread(target=self._sniff, args=(protocol,))
            sniffer.start()
            self._sniffers.append(sniffer)



    def _sniff(self, protocol:str) -> None:
        ports:list                    = self._ports[protocol] if protocol != 'ICMP' else None
        sniffer:BPF_Configured_Socket = self._create_sniffer(protocol, ports)
        packets:list                  = []
        
        while self._running is True:
            readable, _, _= select.select([sniffer], [], [], 0.001)
            if readable:
                packet, _ = sniffer.recvfrom(65535)
                packets.append(packet)

        with self._lock:
            self._responses[protocol] = packets



    def _stop_sniffing(self) -> None:
        self._running = False
        for thread in self._sniffers:
            thread.join()



    def get_packets(self) -> list[dict]:
        self._stop_sniffing()
        return self._responses



    @staticmethod
    def _create_sniffer(protocol:str, ports:list=None) -> BPF_Configured_Socket:
        sniffer:socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sniffer.bind((get_default_iface(), 0))

        bpf_filter:BPF_Instruction = BPF_Filter.get_filter(protocol, ports)
        filter_array:int           = (sock_filter * len(bpf_filter))()
        
        for i, (code, jt, jf, k) in enumerate(bpf_filter):
            filter_array[i] = sock_filter(code, jt, jf, k)

        prog:sock_fprog = sock_fprog(len(bpf_filter), filter_array)

        SO_ATTACH_FILTER:int = 26
        libc:ctypes.CDLL     = ctypes.cdll.LoadLibrary("libc.so.6")
        libc.setsockopt(sniffer.fileno(), socket.SOL_SOCKET, SO_ATTACH_FILTER, ctypes.byref(prog), ctypes.sizeof(prog))

        return sniffer





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