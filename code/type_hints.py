# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


import socket, argparse
from typing import NewType


Raw_Packet = NewType('Raw_Packet', bytes)

BPF_Instruction       = NewType('BPF_Instruction', tuple[int, int, int, int])
BPF_Filter            = NewType('BPF_Filter', list[BPF_Instruction])
BPF_Configured_Socket = NewType('BPF_Configured_Socket', socket.socket)