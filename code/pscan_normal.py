# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import threading, sys, time, random, asyncio
from pkt_builder import Packet
from pkt_sender  import send_layer_3_packet
from sniffer     import Sniffer
from type_hints  import Raw_Packet


class Normal_Scan:

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


    __slots__ = ('_target_ip', '_target_ports', '_arg_flags', '_packets', '_ports_to_sniff', '_delay', '_lock', '_responses')

    def __init__(self, target_ip, ports, arg_flags) -> None:
        self._target_ip:str             = target_ip
        self._target_ports:list[int]    = ports
        self._arg_flags:dict            = arg_flags
        self._packets:list[Raw_Packet]  = None
        self._ports_to_sniff:list[int]  = None
        self._delay:str                 = None
        self._lock                      = threading.Lock()
        self._responses:list[dict]      = list()
        self._sniffer_task:asyncio.Task = None


    def _perform_normal_methods(self) -> None:
        self._create_packets()
        if self._arg_flags['delay']:
            return self._sendings_with_delay()
        return self._send_packets()


    def _create_packets(self) -> None:
        self._packets, self._ports_to_sniff = Packet._create_tcp_packet(self._target_ip, self._target_ports)


    def _start_sniffing(self) -> None:
        self._sniffer_task = asyncio.create_task(Sniffer('IP', self._ports_to_sniff)._sniff())


    async def _send_packets(self) -> list[Packet]:
        for packet, target_port in zip(self._packets, self._target_ports):
            await send_layer_3_packet(packet, self._target_ip, target_port)


    # DELAY METHODS ------------------------------------------------------------------------------------------

    def _sendings_with_delay(self) -> None:
        self._get_delay_time_list()
        threads     = []
        for index ,packet in enumerate(self._packets):
            thread = threading.Thread(target=self._async_send_packet, args=(packet,))
            threads.append(thread)
            thread.start()
            sys.stdout.write(f'\rPacket sent: {index}/{len(self._packets)} - {self._delay[index]:.2}s')
            sys.stdout.flush()
            time.sleep(self._delay[index])
        for thread in threads:
            thread.join()
        print('\n')


    def _get_delay_time_list(self) -> None:
        match self._arg_flags['delay']:
            case True: delay = [random.uniform(1, 3) for _ in range(len(self._packets))]
            case _:    delay = self._create_delay_time_list()
        self._delay = delay


    def _create_delay_time_list(self) -> list:
        values = [float(value) for value in self._arg_flags['delay'].split('-')]
        if len(values) > 1: return [random.uniform(values[0], values[1]) for _ in range(len(self._packets))]
        return [values[0] for _ in range(len(self._packets))]


    """
    def _async_send_packet(self, packet:Packet) -> None:
        response = sr1(packet, timeout=3, verbose=0)
        with self._lock:
            self._responses.append((packet, response))
    """