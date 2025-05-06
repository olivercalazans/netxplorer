# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


from dataclasses    import dataclass
from socket         import gethostbyname
from utils.port_set import Port_Set


@dataclass(slots=True)
class Data:

    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = object().__new__(cls)
        return cls._instance



    command_name:str = None
    arguments:list   = None
    _target_ip:str   = None 
    _ports:dict|list = None



    @property
    def target_ip(self) -> str:
        return self._target_ip

    @target_ip.setter
    def target_ip(self, host_name:str) -> None:
        try:   self._target_ip = gethostbyname(host_name)
        except Exception: raise Exception(f'Unknown host: {host_name}')

    

    @property
    def ports(self) -> dict|list:
        return self._ports
    
    @ports.setter
    def ports(self, ports_str:str) -> None:
        self._ports = Port_Set().get_ports(ports_str)