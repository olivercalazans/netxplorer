# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


from utils.type_hints import BPF_Instruction


class BPF_Filter:

    BPF_MAP = {
        'Jump if EtherType':    lambda jt, jf, d: (0x28, jt, jf, 12),
        'Jump if IPv4':         lambda jt, jf, d: (0x15, jt, jf, 2048),
        'Load IPv4 header':     lambda jt, jf, d: (0x30, jt, jf, 23),
        'Jump if TCP':          lambda jt, jf, d: (0x15, jt, jf, 6),
        'Load dst port':        lambda jt, jf, d: (0x28, jt, jf, 36),
        'Jump if TCP dst port': lambda jt, jf, d: (0x15, jt, jf, d),
        'Jump if ICMP':         lambda jt, jf, d: (0x15, jt, jf, 1),
        'Load ICMP header':     lambda jt, jf, d: (0x30, jt, jf, 20),
        'Jump if Echo Reply':   lambda jt, jf, d: (0x15, jt, jf, 0),
        'Accept packet':        lambda jt, jf, d: (0x06, jt, jf, 0xFFFF),
        'Discard packet':       lambda jt, jf, d: (0x06, jt, jf, 0x0000),
    }


    @staticmethod
    def get_filter(protocol:str, ports:list=None) -> BPF_Instruction:
        match protocol:
            case 'TCP':  return BPF_Filter._get_tcp_parameters(ports)
            case 'ICMP': return BPF_Filter._get_icmp_parameters()


    @staticmethod
    def _get_parameter(type:str, true_jump:int, false_jump:int, dst_port:int=None) -> BPF_Instruction:
        return BPF_Filter.BPF_MAP[type](true_jump, false_jump, dst_port)




    # TCP ====================================================================================================

    @staticmethod
    def _get_tcp_parameters(ports:list) -> BPF_Instruction:
        num:int = len(ports)
        return [
            BPF_Filter._get_parameter('Jump if EtherType', 0, 0),
            BPF_Filter._get_parameter('Jump if IPv4',      0, num + 4),
            BPF_Filter._get_parameter('Load IPv4 header',  0, 0),
            BPF_Filter._get_parameter('Jump if TCP',       0, num + 2),
            BPF_Filter._get_parameter('Load dst port',     0, 0),
           *BPF_Filter._create_tcp_port_parameters(ports),
            BPF_Filter._get_parameter('Accept packet',     0, 0),
            BPF_Filter._get_parameter('Discard packet',    0, 0)
        ]


    @staticmethod
    def _create_tcp_port_parameters(ports:list) -> BPF_Instruction:
        port_parameters:list = [
            BPF_Filter._get_parameter('Jump if TCP dst port', 0, 1, ports[0])
        ]
        
        if len(ports) == 1:
            return port_parameters

        for i, port in enumerate(ports[1:], start=1):
            new_parameter:tuple = BPF_Filter._get_parameter('Jump if TCP dst port', i , 0, port)
            port_parameters.insert(0, new_parameter)
        
        return port_parameters



    # ICMP ===================================================================================================

    @staticmethod
    def _get_icmp_parameters() -> BPF_Instruction:
        return [
            BPF_Filter._get_parameter('Jump if EtherType',  0, 0),
            BPF_Filter._get_parameter('Jump if IPv4',       0, 5),
            BPF_Filter._get_parameter('Load IPv4 header',   0, 0),
            BPF_Filter._get_parameter('Jump if ICMP',       0, 3),
            BPF_Filter._get_parameter('Load ICMP header',   0, 0),
            BPF_Filter._get_parameter('Jump if Echo Reply', 0, 1),
            BPF_Filter._get_parameter('Accept packet',      0, 0),
            BPF_Filter._get_parameter('Discard packet',     0, 0)
        ]