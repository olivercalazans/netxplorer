# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket, ctypes
from pkt_dissector import Dissector
from type_hints    import BPF_Instruction, BPF_Configured_Socket


class Sniffer:

    def __init__(self, interface:str, protocol:str, ports:list=None) -> None:
        self._interface:str   = interface
        self._protocol:str    = protocol
        self._ports:list[int] = ports



    def _sniffer(self) -> BPF_Configured_Socket:
        sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sniffer.bind((self._interface, 0))

        bpf_filter = self._define_filter()

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
        port_parameters = self._create_port_filter()
        num             = len(port_parameters)
        parameters      = [
            (0x15, 0, num + 4, 2048), #...: Jump if EtherType == IPv4
            (0x30, 0, 0, 23), #...........: Load IP Protocol
            (0x15, 0, num + 2, 6), #......: Jump if Protocol == TCP
            (0x28, 0, 0, 36) #............: Load Destination Port
        ]
        return parameters + port_parameters



    def _create_port_filter(self) -> BPF_Instruction:
        len_ports       = len(self._ports)
        port_parameters = list()
        for i, port in enumerate(self._ports):
            true_jump  = len_ports - (i+1)
            false_jump = 0 if i + 1 < len_ports else 1 
            port_parameters.append((0x15, true_jump, false_jump, port))
        return port_parameters



    def _sniff_ip_packets(self):
        sniffer = self._sniffer()
        try:
            packet_info = list()
            while True:
                packet, _ = sniffer.recvfrom(65535)
                result = Dissector(packet)._dissect_tcp_ip_packet()
                print(f"IP Packet: Source: {result['ip']}, Source Port: {result['port']}, Flags {result['flags']}")
        except KeyboardInterrupt:
            print("\nSniffing stopped.")
        finally:
            sniffer.close()



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




if __name__ == "__main__":
    x = Sniffer("wlp2s0", 'IP', [0x04d2])
    z = x._sniff_ip_packets()