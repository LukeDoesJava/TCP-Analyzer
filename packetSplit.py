from statistics import mean
from struct import *
from packet_struct import *

# START OF PACKET SPLITTING FUNCTIONS
def retrieve_global_header(f):
    read_g_header = f.read(24)
    g_hdr = pcap_hdr_s()
    g_hdr.unpack_global_header(read_g_header)
    return g_hdr

def retrieve_packet_header(f, byte_order):
    read_p_header = f.read(16)
    if not read_p_header:
        return None
    p_hdr = pcaprec_hdr_s()
    p_hdr.unpack_packet_header(read_p_header, byte_order)
    return p_hdr

def retrieve_ethernet_header(packet_data):
    read_eth_header = packet_data[:14]
    eth_hdr = ethernet_header()
    eth_hdr.unpack_eth_header(read_eth_header)
    return eth_hdr

def retrieve_ip_header(packet_data):
    read_IP_header = packet_data[:20]
    ip_hdr = IP_Header()
    ip_hdr.get_IP(read_IP_header[12:16], read_IP_header[16:20])
    ip_hdr.get_header_len(read_IP_header[0:1])
    ip_hdr.get_total_len(read_IP_header[2:4])
    ip_hdr.get_protocol(read_IP_header[9:10])
    return ip_hdr

def retrieve_tcp_header(packet_data):
    read_tcp_header = packet_data[:20]
    tcp_hdr = TCP_Header()
    tcp_hdr.get_src_port(read_tcp_header[0:2])
    tcp_hdr.get_dst_port(read_tcp_header[2:4])
    tcp_hdr.get_seq_num(read_tcp_header[4:8])
    tcp_hdr.get_ack_num(read_tcp_header[8:12])
    tcp_hdr.get_data_offset(read_tcp_header[12:13])  
    tcp_hdr.get_flags(read_tcp_header[13:14])
    tcp_hdr.get_window_size(read_tcp_header[14:15], read_tcp_header[15:16])
    return tcp_hdr

def generate_packet(ip_hdr, tcp_hdr, packet_count, p_hdr, orig_time, packet_data):
    pck = packet()
    pck.IP_header = ip_hdr
    pck.TCP_header = tcp_hdr
    pck.packet_No_set(packet_count)
    pck.timestamp_set(struct.pack('I', p_hdr.ts_sec), struct.pack('I' , p_hdr.ts_usec), orig_time)
    pck.buffer = packet_data
    return pck
# END OF PACKET SPLITTING FUNCTIONS