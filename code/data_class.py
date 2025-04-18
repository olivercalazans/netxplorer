# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


from dataclasses import dataclass
from socket      import gethostbyname


@dataclass(slots=True)
class Data:
    _command_name:str = None
    _arguments:list   = None
    _target_ip:str    = None 
    _ports:dict|list  = None


    @property
    def target_ip(self):
        return self._target_ip

    @target_ip.setter
    def target_ip(self, value:str):
        try:   self._target_ip = gethostbyname(value)
        except Exception: raise ValueError(f'Unknown host: {value}')