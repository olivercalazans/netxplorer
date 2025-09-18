import struct
import socket
from utils.network_info import get_my_ip_address
from utils.type_hints   import BPF_Instruction


class BPF_Filter:

    @staticmethod
    def get_filter(protocol:str) -> BPF_Instruction:
        match protocol:
            case 'TCP':      return BPF_Filter._get_tcp_responses_parameters()
            case 'UDP':      return BPF_Filter._get_udp_responses_parameters()
            case 'TCP-ICMP': return BPF_Filter._get_tcp__and_icmp_responses_parameters()



    @staticmethod
    def _get_tcp_responses_parameters() -> BPF_Instruction:
        my_ip_hex:int = struct.unpack('!I', socket.inet_aton(get_my_ip_address()))[0]
        return [
            (0x28, 0,  0, 0x0000000c), # Load EtherType field (offset 12)
            (0x15, 0, 11, 0x00000800), # If not IPv4 (0x0800), jump to end
            (0x20, 0,  0, 0x0000001e), # Load destination IP address (offset 30)
            (0x15, 0,  9, my_ip_hex),  # If not my IP, jump
            (0x30, 0,  0, 0x00000017), # Load IP protocol field (offset 23)
            (0x15, 0,  7, 0x00000006), # If not TCP (protocol 6), jump
            (0x28, 0,  0, 0x00000014), # Load IP flags/fragment offset field
            (0x45, 5,  0, 0x00001fff), # If packet is fragmented, jump
            (0xb1, 0,  0, 0x0000000e), # Calculate TCP header offset (IHL * 4)
            (0x50, 0,  0, 0x0000001b), # Load TCP flags byte (offset 27 from IP header)
            (0x54, 0,  0, 0x00000012), # Mask with SYN+ACK (0x12)
            (0x15, 0,  1, 0x00000012), # If flags are exactly SYN+ACK, continue
            (0x6,  0,  0, 0x00040000), # Accept packet (return up to 262144 bytes)
            (0x6,  0,  0, 0x00000000), # Reject everything else
        ]
    


    @staticmethod
    def _get_tcp__and_icmp_responses_parameters() -> BPF_Instruction:
        my_ip_hex:int = struct.unpack('!I', socket.inet_aton(get_my_ip_address()))[0]
        return [
            (0x28,  0,  0, 0x0000000c), # Load EtherType (offset 12) into A
            (0x15,  0, 19, 0x00000800), # If EtherType != IPv4 (0x0800), jump to reject
            (0x20,  0,  0, 0x0000001e), # Load destination IP (offset 30) into A
            (0x15,  0, 17, my_ip_hex),  # If dest IP != my IP, jump to reject
            (0x30,  0,  0, 0x00000017), # Load IP protocol (offset 23) into A
            (0x15,  0,  5, 0x00000001), # If protocol == ICMP (0x01), jump ahead to ICMP check
            (0x28,  0,  0, 0x00000014), # Load IP flags/frag offset
            (0x45, 13,  0, 0x00001fff), # If fragmented, skip all (frag != 0), jump to reject
            (0xb1,  0,  0, 0x0000000e), # A = A + 14 (to get start of IP header)
            (0x50,  0,  0, 0x0000000e), # Load ICMP type (offset 14) into A
            (0x15,  9, 10, 0x00000000), # If ICMP type == 0 (Echo Reply), accept
            (0x15,  0,  9, 0x00000006), # If not TCP (protocol != 6), jump to reject
            (0x28,  0,  0, 0x00000014), # Load IP flags/frag offset again (needed for TCP branch)
            (0x45,  7,  0, 0x00001fff), # If fragmented, reject
            (0xb1,  0,  0, 0x0000000e), # A = A + 14 again
            (0x50,  0,  0, 0x0000001b), # Load TCP flags (offset 27 from IP header)
            (0x54,  0,  0, 0x00000012), # Mask flags with SYN (0x02) + ACK (0x10)
            (0x15,  2,  0, 0x00000012), # If SYN-ACK, accept
            (0x50,  0,  0, 0x0000001b), # Load TCP flags again
            (0x45,  0,  1, 0x00000004), # If RST bit set, accept
            (0x6,   0,  0, 0x00040000), # Accept packet (return 262144 bytes)
            (0x6,   0,  0, 0x00000000), # Reject otherwise
        ]


    @staticmethod
    def _get_udp_responses_parameters() -> list[tuple]:
        my_ip_hex:int = struct.unpack('!I', socket.inet_aton(get_my_ip_address()))[0]
        return [
            (0x28, 0,  0, 0x0000000c), # Load 2 bytes from [12] (EtherType)
            (0x15, 0, 12, 0x00000800), # If EtherType != 0x0800 (IPv4), jump to reject
            (0x20, 0,  0, 0x0000001e), # Load 4 bytes from [30] (IP dst addr)
            (0x15, 0, 10, my_ip_hex),  # If dst IP != my IP, jump to reject
            (0x30, 0,  0, 0x00000017), # Load 1 byte from [23] (IP protocol)
            (0x15, 0,  8, 0x00000001), # If protocol != 1 (ICMP), jump to reject
            (0x28, 0,  0, 0x00000014), # Load 2 bytes from [20] (IP flags+frag offset)
            (0x45, 6,  0, 0x00001fff), # Check for fragmentation; if fragmented, reject
            (0xb1, 0,  0, 0x0000000e), # Adjust offset (A += 14)
            (0x50, 0,  0, 0x0000000e), # Load 1 byte from [A+14] (ICMP type)
            (0x15, 0,  3, 0x00000003), # If ICMP type != 3 (dest unreachable), reject
            (0x50, 0,  0, 0x0000000f), # Load 1 byte from [A+15] (ICMP code)
            (0x15, 0,  1, 0x00000003), # If ICMP code != 3 (port unreachable), reject
            (0x6,  0,  0, 0x00040000), # Accept packet (return 262144 bytes)
            (0x6,  0,  0, 0x00000000), # Reject packet
        ]