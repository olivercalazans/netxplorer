# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket, ctypes, asyncio
from pkt_dissector import Dissector
from network       import get_default_iface
from type_hints    import BPF_Instruction, BPF_Configured_Socket


class Sniffer:

    __slots__ = ('_protocol', '_ports', '_sniffer', '_running', '_task', '_packet_queue', '_loop')

    def __init__(self, protocol:str, ports:list) -> None:
        self._protocol:str                  = protocol
        self._ports:list[int]               = ports
        self._sniffer:BPF_Configured_Socket = None
        self._running:bool                  = False
        self._task: asyncio.Task            = None
        self._packet_queue                  = asyncio.Queue()
        self._loop                          = asyncio.get_event_loop()


    
    async def __aenter__(self):
        await self._start()
        return self
    
    async def _start(self) -> None:
        if self._running: return
        self._running = True
        self._sniffer = self._create_sniffer()
        self._sniffer.setblocking(False)
        self._task = asyncio.create_task(self._sniff_loop())


    async def __aexit__(self, exc_type, exc_value, traceback):
        await self._stop()
        return False

    async def _stop(self) -> None:
        self._running = False
        if self._sniffer:
            self._sniffer.close()
        await self._task



    async def _get_packets(self) -> list[dict]:
        packets = []
        try:
            while True:
                packets.append(await asyncio.wait_for(self._packet_queue.get(), 5))
        except asyncio.TimeoutError:
            pass
        return self._process_packets(packets)



    async def _sniff_loop(self):
        while self._running:
            try:
                packet = await self._loop.sock_recv(self._sniffer, 65535)
                await self._packet_queue.put(packet)
            except (BlockingIOError, OSError):
                await asyncio.sleep(0.01)



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

        return sniffer



    def _define_filter(self) -> BPF_Instruction:
        FILTERS = {
            'IP':  self._get_ip_filter_parameters(),
            'ARP': [(0x15, 0, 3, 0x0806)] #.......: Jump if EtherType == ARP (0x0806)
        }
        filter  = [(0x28, 0, 0, 12)] #............: Load EtherType (offset 12)
        filter += FILTERS.get(self._protocol) #...: Specific parameters
        filter += [(0x06, 0, 0, 0xFFFF), #........: Accept packet
                   (0x06, 0, 0, 0x0000)] #........: Discard packet
        return filter



    def _get_ip_filter_parameters(self) -> BPF_Instruction:
        port_jumps = self._create_port_jumps()
        num        = len(port_jumps)
        parameters = [
            (0x15, 0, num + 4, 2048), #...: Jump if EtherType == IPv4
            (0x30, 0, 0, 23), #...........: Load IP Protocol
            (0x15, 0, num + 2, 6), #......: Jump if Protocol == TCP
            (0x28, 0, 0, 36) #............: Load Destination Port
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
    def _process_packets(packets) -> list[dict]:
        with Dissector() as DISSECTOR:
            return DISSECTOR._dissect(packets)




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