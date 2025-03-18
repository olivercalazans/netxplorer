# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import threading, sys, time, random
from pkt_builder import Packet
from pkt_sender  import send_layer_3_packet
from sniffer     import Sniffer
from type_hints  import Raw_Packet


class Normal_Scan:

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


    __slots__ = ('_target_ip', '_target_ports', '_args', '_packets', '_ports_to_sniff', '_lock', '_responses')

    def __init__(self, target_ip, ports, arg_flags) -> None:
        self._target_ip:str            = target_ip
        self._target_ports:list[int]   = ports
        self._args:dict                 = arg_flags
        self._packets:list[Raw_Packet] = None
        self._ports_to_sniff:list[int] = None
        self._lock                     = threading.Lock()
        self._responses:list[dict]     = list()


    def _perform_normal_methods(self) -> None:
        self._create_packets()
        return self._send_and_receive()


    def _create_packets(self) -> None:
        self._packets, self._ports_to_sniff = Packet()._create_tcp_packet(self._target_ip, self._target_ports)


    def _send_and_receive(self) -> None:
        with Sniffer('IP', self._ports_to_sniff) as sniffer:
            self._send_packets()
            time.sleep(3)
            return sniffer._get_result()


    def _send_packets(self) -> None:
        delay_list = self._get_delay_time_list()
        index      = 1
        for delay, packet, port in zip(delay_list, self._packets, self._target_ports):
            time.sleep(delay)
            send_layer_3_packet(packet, self._target_ip, port)
            sys.stdout.write(f'\rPacket sent: {index}/{len(self._packets)} - {delay}s')
            sys.stdout.flush()
            index += 1
        print('\n')


    def _get_delay_time_list(self) -> list[int]:
        if self._args['delay'] is False:
            return [0 for _ in range(len(self._packets))]
        elif self._args['delay'] is True:
            return [0] + [random.uniform(1, 3) for _ in range(len(self._packets) - 1)]
        
        values = [float(value) for value in self._args['delay'].split('-')]
        if len(values) > 1:
            return [0] + [random.uniform(values[0], values[1]) for _ in range(len(self._packets) - 1)]
        return [0] + [values[0] for _ in range(len(self._packets) - 1)]



x = Normal_Scan('192.168.1.1', [22, 23, 443, 445], {'delay': False})
z = x._perform_normal_methods()
print(z)