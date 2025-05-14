# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket
import ctypes
import select
from threading           import Thread
from queue               import Queue
from models.data         import Data
from sniffing.bpf_filter import BPF_Filter
from utils.network_info  import get_default_iface
from utils.type_hints    import BPF_Instruction, BPF_Configured_Socket, Raw_Packet


class Sniffer:

    _instance:"Sniffer" = None
    
    def __new__(cls, *args, **kwargs) -> None:
        if cls._instance is None:
            cls._instance = object().__new__(cls)
        return cls._instance

    

    __slots__ = ('_data', '_protocols', '_running', '_sniffer', '_thread_sniffer', '_thread_store', '_queue')

    def __init__(self, data:Data, protocols:str) -> None:
        self._data:Data                     = data
        self._protocols:list                = protocols
        self._running:bool                  = True
        self._sniffer:BPF_Configured_Socket = None
        self._thread_sniffer:Thread         = None
        self._thread_store:Thread           = None
        self._queue:Queue                   = Queue()

    

    def __enter__(self):
        self._create_sniffer()
        self._start_sniffing()
        return self
    

    def __exit__(self, exc_type, exc_value, traceback):
        self.__class__._instance = None
        return False



    def _start_sniffing(self) -> None:
        self._thread_store   = Thread(target=self._store_packets)
        self._thread_sniffer = Thread(target=self._sniff)
        self._thread_store.start()
        self._thread_sniffer.start()



    def _sniff(self) -> None:
        while self._running is True:
            readable, _, _= select.select([self._sniffer], [], [], 0.001)
            if readable:
                packet, _ = self._sniffer.recvfrom(65535)
                self._queue.put(packet)


    
    def _store_packets(self) -> None:
        while self._running or not self._queue.empty():
            try:
                packet:Raw_Packet = self._queue.get(timeout=0.1)
                self._data.raw_packets.append(packet)
            except:
                continue



    def stop_sniffing(self) -> list[dict]:
        self._running = False
        self._thread_sniffer.join()
        self._thread_store.join()
        self._sniffer.close()



    def _create_sniffer(self) -> BPF_Configured_Socket:
        sniffer:socket.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sniffer.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        sniffer.bind((get_default_iface(), 0))

        bpf_filter:BPF_Instruction = BPF_Filter.get_filter(self._protocols)
        filter_array:int           = (sock_filter * len(bpf_filter))()
        
        for i, (code, jt, jf, k) in enumerate(bpf_filter):
            filter_array[i] = sock_filter(code, jt, jf, k)

        prog:sock_fprog = sock_fprog(len(bpf_filter), filter_array)

        SO_ATTACH_FILTER:int = 26
        libc:ctypes.CDLL     = ctypes.cdll.LoadLibrary("libc.so.6")
        libc.setsockopt(
            sniffer.fileno(),
            socket.SOL_SOCKET,
            SO_ATTACH_FILTER,
            ctypes.byref(prog),
            ctypes.sizeof(prog)
        )

        self._sniffer = sniffer





# Defines a BPF filter structure
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