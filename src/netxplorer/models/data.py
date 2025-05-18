# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


from dataclasses      import dataclass, field
from socket           import gethostbyname
from utils.port_set   import Port_Set
from utils.type_hints import Raw_Packet


@dataclass(slots=True)
class Data:

    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = object().__new__(cls)
        return cls._instance



    command_name:str             = None
    arguments:list               = None
    _target_ip:str               = None 
    _target_ports:list           = None
    raw_packets:list[Raw_Packet] = field(default_factory=list)
    _responses:dict[list]        = field(default_factory=lambda: {'TCP':set(), 'UDP':set(), 'ICMP':set()})



    @property
    def target_ip(self) -> str:
        return self._target_ip

    @target_ip.setter
    def target_ip(self, host_name:str|list) -> None:
        try:
            if isinstance(host_name, list):
                self._target_ip = [gethostbyname(host) for host in host_name]
            else:
                self._target_ip = gethostbyname(host_name)
        except Exception:
            raise Exception(f'Unknown host: {host_name}')

    

    @property
    def target_ports(self) -> list:
        return self._target_ports
    
    @target_ports.setter
    def target_ports(self, input_ports:str) -> None:
        self._target_ports = Port_Set.get_ports(input_ports)


    
    @property
    def responses(self) -> dict[list]:
        return self._responses
    
    def add_packet(self, protocol:str, packet_info:tuple) -> None:
        if packet_info[0] in self._target_ip:
            self._responses[protocol].add(packet_info)