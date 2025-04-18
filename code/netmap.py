# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import time
from sniffer       import Sniffer
from pkt_builder   import ICMP
from net_info      import get_ip_range, get_host_name
from pkt_sender    import send_ping
from pkt_dissector import dissect_icmp_packet
from type_hints    import Raw_Packet


class Network_Mapper:

    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = object().__new__(cls)
        return cls._instance



    __slots__ = ()

    def __init__(self, _) -> None:
        pass

    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        return False



    def _execute(self) -> None:
        try:
            self._perform_ping_sweep()
        except KeyboardInterrupt:  print('Process stopped')
        except Exception as error: print(f'ERROR: {error}')



    # PING ---------------------------------------------------------------------------

    def _perform_ping_sweep(self) -> None:
        packets = None
        with Sniffer('ICMP') as sniffer:
            self._ping_sweep()
            time.sleep(3)
            packets = sniffer._get_packets()
        self._display_ping_result(packets)
    


    @staticmethod
    def _ping_sweep() -> None:
        PACKET = ICMP()
        for ip in get_ip_range():
            send_ping(PACKET, ip)



    @staticmethod
    def _display_ping_result(packets:list[Raw_Packet]) -> None:
        print(f'IP Address{8*" "}MAC Address{9*" "}Hostname')
        for pkt in packets:
            src_ip, mac_addr = dissect_icmp_packet(pkt)
            hostname         = get_host_name(src_ip)
            print(f'{src_ip:<15} - {mac_addr} - {hostname}')
        print(f'Total: {len(packets)} active hosts')