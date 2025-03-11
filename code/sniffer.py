# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket, ctypes, struct


# Define a estrutura do filtro BPF
class sock_filter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint),
    ]


# Define a estrutura do filtro BPF completo
class sock_fprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.POINTER(sock_filter)),
    ]


def sniff(interface):
    # Cria o socket raw
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sniffer.bind((interface, 0))

    # Define o filtro BPF
    bpf_filter = [
        (0x28, 0, 0, 0x0000000c),  # Load Ethernet type (offset 12)
        (0x15, 0, 1, 0x00000800),  # Jump if Ethernet type == IPv4 (0x0800)
        (0x06, 0, 0, 0x0000ffff),  # Retain packet
        (0x06, 0, 0, 0x00000000),  # Discard packet
    ]

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



def sniff_ip_packets(interface):
    sniffer = sniff(interface)
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




if __name__ == "__main__":
    sniff_ip_packets("wlp2s0")