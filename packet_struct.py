import struct
# GLOBAL HEADER
class pcap_hdr_s:
    magic_number = 0
    version_major = 0
    version_minor = 0
    thiszone = 0
    sigfigs = 0
    snaplen = 0
    network = 0
    
    def __init__(self):
        self.magic_number = 0
        self.version_major = 0
        self.version_minor = 0
        self.thiszone = 0
        self.sigfigs = 0
        self.snaplen = 0
        self.network = 0
        
    def unpack_global_header(self,buffer):
        unpacked_data = struct.unpack('IHHIIII',buffer)
        self.magic_number = unpacked_data[0]
        self.version_major = unpacked_data[1]
        self.version_minor = unpacked_data[2]
        self.thiszone = unpacked_data[3]
        self.sigfigs = unpacked_data[4]
        self.snaplen = unpacked_data[5]
        self.network = unpacked_data[6]

    def get_endianness(self):
        if self.magic_number == 0xa1b2c3d4:
            return 'big'
        elif self.magic_number == 0xd4c3b2a1:
            return 'little'
        elif self.magic_number == 0:
            return 'unset magic number'
        else:
            return 'unrecognized'

# PACKET HEADER
class pcaprec_hdr_s:
    ts_sec = 0
    ts_usec = 0
    incl_len = 0
    orig_len = 0
    
    def __init__(self):
        self.ts_sec = 0
        self.ts_usec = 0
        self.incl_len = 0
        self.orig_len = 0
        
    def unpack_packet_header(self,buffer, byte_order):
        self.ts_sec = struct.unpack(byte_order + 'I', buffer[0:4])[0]
        self.ts_usec = struct.unpack(byte_order + 'I', buffer[4:8])[0]
        self.incl_len = struct.unpack(byte_order + 'I', buffer[8:12])[0]
        self.orig_len = struct.unpack(byte_order + 'I', buffer[12:16])[0]

    def get_incl_len(self):
        return self.incl_len
    
    def get_orig_len(self):
        return self.orig_len
    
# PACKET CLASSES
class ethernet_header:
    dest_mac = None
    src_mac = None
    eth_type = None
    
    def __init__(self):
        self.dest_mac = None
        self.src_mac = None
        self.eth_type = None
    
    def unpack_eth_header(self, buffer):
        dest_mac = struct.unpack('BBBBBB', buffer[0:6])
        src_mac = struct.unpack('BBBBBB', buffer[6:12])
        eth_type = struct.unpack('H', buffer[12:14])

    def get_dest_mac(self):
        return self.dest_mac
    def get_src_mac(self):
        return self.src_mac
    def get_eth_type(self):
        return self.eth_type
    

class IP_Header:
    src_ip = None #<type 'str'>
    dst_ip = None #<type 'str'>
    ip_header_len = None #<type 'int'>
    total_len = None    #<type 'int'>
    protocol = None
    
    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0
        self.total_len = 0
    
    def ip_set(self,src_ip,dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
    
    def header_len_set(self,length):
        self.ip_header_len = length
    
    def total_len_set(self, length):
        self.total_len = length    
        
    def get_IP(self,buffer1,buffer2):
        src_addr = struct.unpack('BBBB',buffer1)
        dst_addr = struct.unpack('BBBB',buffer2)
        s_ip = str(src_addr[0])+'.'+str(src_addr[1])+'.'+str(src_addr[2])+'.'+str(src_addr[3])
        d_ip = str(dst_addr[0])+'.'+str(dst_addr[1])+'.'+str(dst_addr[2])+'.'+str(dst_addr[3])
        self.ip_set(s_ip, d_ip)
        
    def get_header_len(self,value):
        result = struct.unpack('B', value)[0]
        length = (result & 15)*4
        self.header_len_set(length)

    def get_total_len(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        length = num1+num2+num3+num4
        self.total_len_set(length)

    def get_protocol(self,buffer):
        protocol = struct.unpack('B',buffer)[0]
        self.protocol = protocol

class TCP_Header:
    src_port = 0
    dst_port = 0
    seq_num = 0
    ack_num = 0
    data_offset = 0
    flags = {}
    window_size =0
    checksum = 0
    ugp = 0
    
    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.seq_num = 0
        self.ack_num = 0
        self.data_offset = 0
        self.flags = {}
        self.window_size =0
        self.checksum = 0
        self.ugp = 0
    
    def src_port_set(self, src):
        self.src_port = src
        
    def dst_port_set(self,dst):
        self.dst_port = dst
        
    def seq_num_set(self,seq):
        self.seq_num = seq
        
    def ack_num_set(self,ack):
        self.ack_num = ack
        
    def data_offset_set(self,data_offset):
        self.data_offset = data_offset
        
    def flags_set(self,ack, rst, syn, fin):
        self.flags["ACK"] = ack
        self.flags["RST"] = rst
        self.flags["SYN"] = syn
        self.flags["FIN"] = fin
    
    def win_size_set(self,size):
        self.window_size = size
        
    def get_src_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.src_port_set(port)
        #print(self.src_port)
        return None
    
    def get_dst_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.dst_port_set(port)
        #print(self.dst_port)
        return None
    
    def get_seq_num(self,buffer):
        seq = struct.unpack(">I",buffer)[0]
        self.seq_num_set(seq)
        #print(seq)
        return None
    
    def get_ack_num(self,buffer):
        ack = struct.unpack('>I',buffer)[0]
        self.ack_num_set(ack)
        return None
    
    def get_flags(self,buffer):
        value = struct.unpack("B",buffer)[0]
        fin = value & 1
        syn = (value & 2)>>1
        rst = (value & 4)>>2
        ack = (value & 16)>>4
        self.flags_set(ack, rst, syn, fin)
        return None
    def get_window_size(self,buffer1,buffer2):
        buffer = buffer2+buffer1
        size = struct.unpack('H',buffer)[0]
        self.win_size_set(size)
        return None
        
    def get_data_offset(self,buffer):
        value = struct.unpack("B",buffer)[0]
        length = ((value & 240)>>4)*4
        self.data_offset_set(length)
        #print(self.data_offset)
        return None
    
    def relative_seq_num(self,orig_num):
        if(self.seq_num>=orig_num):
            relative_seq = self.seq_num - orig_num
            self.seq_num_set(relative_seq)
        #print(self.seq_num)
        
    def relative_ack_num(self,orig_num):
        if(self.ack_num>=orig_num):
            relative_ack = self.ack_num-orig_num+1
            self.ack_num_set(relative_ack)
   

class packet():
    
    #pcap_hd_info = None
    IP_header = None
    TCP_header = None
    timestamp = 0
    packet_No = 0
    RTT_value = 0
    RTT_flag = False
    buffer = None
    
    
    def __init__(self):
        self.IP_header = IP_Header()
        self.TCP_header = TCP_Header()
        #self.pcap_hd_info = pcap_ph_info()
        self.timestamp = 0
        self.packet_No =0
        self.RTT_value = 0.0
        self.RTT_flag = False
        self.buffer = None
        
    def timestamp_set(self,buffer1,buffer2,orig_time):
        seconds = struct.unpack('I',buffer1)[0]
        microseconds = struct.unpack('<I',buffer2)[0]
        self.timestamp = round(seconds+microseconds*0.000001-orig_time,6)
        #print(self.timestamp,self.packet_No)
    def packet_No_set(self,number):
        self.packet_No = number
        #print(self.packet_No)
        
    def get_RTT_value(self,p):
        rtt = p.timestamp-self.timestamp
        self.RTT_value = round(rtt,8)