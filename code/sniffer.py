# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket, ctypes, struct


class Sniffer:

    def __init__(self, interface:str, ports:list[int]):
        self._interface:str   = interface
        self._ports:list[int] = ports



    def _sniffer(self):
        sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sniffer.bind((self._interface, 0))

        bpf_filter = self._define_filter('IP')

        # Converte o filtro BPF para a estrutura do sistema
        filter_array = (sock_filter * len(bpf_filter))()
        for i, (code, jt, jf, k) in enumerate(bpf_filter):
            filter_array[i] = sock_filter(code, jt, jf, k)

        prog = sock_fprog(len(bpf_filter), filter_array)

        # Usa ctypes para definir SO_ATTACH_FILTER
        SO_ATTACH_FILTER = 26
        libc = ctypes.cdll.LoadLibrary("libc.so.6")
        libc.setsockopt(sniffer.fileno(), socket.SOL_SOCKET, SO_ATTACH_FILTER, ctypes.byref(prog), ctypes.sizeof(prog))

        return sniffer



    @staticmethod
    def _define_filter(filter_type:str) -> list[tuple]:
        FILTERS = {
            'IP': [
                (0x15, 0, 3, 0x0800),    # Jump if EtherType == IPv4 (0x0800)
                (0x30, 0, 0, 0x09),      # Load IP Protocol (offset 9)
                (0x15, 0, 2, 0x06),      # Jump if Protocol == TCP (0x06)
                #(0x28, 0, 0, 0x16),      # Load Destination Port (offset 36)
                #(0x15, 0, 2, 23432),     # Jump if Port == 23432
            ],

            'ARP': [
                (0x15, 0, 3, 0x0806),    # Jump if EtherType == ARP (0x0806)
            ]
        }
        
        filter  = [(0x28, 0, 0, 0x0000000c)]    # Load EtherType (offset 12)
        filter += FILTERS.get(filter_type)
        filter += [
            (0x06, 0, 0, 0xFFFF),    # Accept packet
            (0x06, 0, 0, 0x0000)     # Discard packet
        ]
        return filter



    @staticmethod
    def _get_port_code(protocol:str) -> tuple[int]:
        PORT_CODE = {
            'TCP':  0x06,
            'UDP':  0x11,
            'ICMP': 0x01
        }
        return (0x15, 0, 0, PORT_CODE.get(protocol))



    def _sniff_ip_packets(self):
        sniffer = self._sniffer()
        try:
            while True:
                # Captura um pacote
                packet, _ = sniffer.recvfrom(65535)

                # Extrai o cabeçalho Ethernet (14 bytes)
                eth_header = packet[:14]
                eth_protocol = struct.unpack('!H', eth_header[12:14])[0]

                # Verifica se o protocolo Ethernet é IP (0x0800)
                if eth_protocol == 0x0800:
                    # Extrai o cabeçalho IP (20 bytes)
                    ip_header = packet[14:34]

                    # Desempacota o cabeçalho IP
                    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

                    version_ihl = iph[0]
                    version = version_ihl >> 4
                    ihl = version_ihl & 0xF

                    iph_length = ihl * 4

                    ttl = iph[5]
                    protocol = iph[6]
                    s_addr = socket.inet_ntoa(iph[8])
                    d_addr = socket.inet_ntoa(iph[9])

                    print(f"IP Packet: Source: {s_addr}, Destination: {d_addr}, Protocol: {protocol}, TTL: {ttl}")

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
    x = Sniffer("wlp2s0", [22])
    x._sniff_ip_packets()
