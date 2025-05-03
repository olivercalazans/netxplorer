# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


from dataclasses import dataclass
from socket      import gethostbyname


@dataclass(slots=True)
class Data:

    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = object().__new__(cls)
        return cls._instance
    

    command_name:str = None
    arguments:list   = None
    target_ip:str    = None 
    ports:dict|list  = None


    @property
    def _target_ip(self) -> str:
        return self.target_ip

    @_target_ip.setter
    def _target_ip(self, value:str) -> None:
        try:   self.target_ip = gethostbyname(value)
        except Exception: raise ValueError(f'Unknown host: {value}')