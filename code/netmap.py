# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


from net_info   import get_subnet_mask, get_ip_range, get_buffer_size
from pkt_sender import send_ping
from display    import *


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

    def _ping_sweep(self) -> None:
        ...