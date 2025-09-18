import socket
from typing import NewType


BPF_Instruction       = NewType('BPF_Instruction', tuple[int, int, int, int])
BPF_Configured_Socket = NewType('BPF_Configured_Socket', socket.socket)
Raw_Packet            = NewType('Raw_Packet', bytes)