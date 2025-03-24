# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import time
from sniffer       import Sniffer
from pkt_builder   import ICMP
from net_info      import get_ip_range
from pkt_sender    import send_ping
from pkt_dissector import dissect_icmp_packet
from type_hints    import Raw_Packet
from display       import *


class Network_Mapper:

    __slots__ = ('_flags')

    def __init__(self, arguments:dict) -> None:
        self._flags:dict = arguments



    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        return False



    def _execute(self) -> None:
        try:
            self._ping_sweep()
        except KeyboardInterrupt:   display_process_stopped()
        except ValueError as error: display_error(error)
        except Exception as error:  display_unexpected_error(error)



    # PING ---------------------------------------------------------------------------

    def _performe_ping_sweep(self) -> None:
        packets = None
        with Sniffer('ICMP') as sniffer:
            self._ping_sweep()
            time.sleep(2)
            packets = sniffer._get_packets()
        self._display_ping_result(packets)
    


    @staticmethod
    def _ping_sweep() -> None:
        PACKET = ICMP()
        for ip in get_ip_range():
            send_ping(PACKET, ip)



    @staticmethod
    def _display_ping_result(packets:list[Raw_Packet]) -> None:
        for pkt in packets:
            src_ip = dissect_icmp_packet(pkt)
            print(f'{green("Active Host")}: {src_ip}')
        print(f'Total {len(packets)} active hosts')