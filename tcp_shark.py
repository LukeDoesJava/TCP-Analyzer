import argparse
from statistics import mean
from struct import *
import sys
from packet_struct import *
import packetSplit
import connectionSort

# START OF QUESTION ANSWER FUNCTIONS
def print_a(connections):
    response = "a) Total number of connections: "
    response += str(len(connections))
    print(response)
    return

def print_b(connection_dict):
    count = 1
    response = "b) Connections' details: "
    for connection in connection_dict:
        connection_details = connection_dict.get(connection)
        was_reset = False
        if connection_details.get("status")[2] >= 1:
            was_reset = True
        response += "\nConnection " + str(count) + ":\n"
        response += "Source Address: " + str(connection[0]) + "\n"
        response += "Destination Address: " + str(connection[2]) + "\n"
        response += "Source Port: " + str(connection[1]) + "\n"
        response += "Destination Port: " + str(connection[3]) + "\n"
        response += "Status: " + "S" + str(connection_details.get("status")[0]) + "F" + str(connection_details.get("status")[1]) + ("/R" if was_reset else "") + "\n"
        if connection_details.get("status")[0] >= 1 and connection_details.get("status")[1] >= 1: # If it was not terminated, stop printing rest of data
            response += "Start time: " + str(connection_details.get("in_order")[0].timestamp) + " seconds \n"
            response += "End time: " + str(connection_details.get("in_order")[connection_details.get("packet_amount")-1].timestamp) + " seconds\n"
            response += "Duration: " + str(connection_details.get("duration")) + " seconds\n"
            response += "Number of packets sent from Source to Destination: " + str(len(connection_details.get("forward"))) + "\n"
            response += "Number of packets sent from Destination to Source: " + str(len(connection_details.get("backward"))) + "\n"
            response += "Total number of packets: " + str(len(connection_details.get("forward")) + len(connection_details.get("backward"))) + "\n"
            response += "Number of data bytes sent from Source to Destination: " + str((connection_details.get("sent_bytes"))) + "\n"
            response += "Number of data bytes sent from Destination to Source: " + str((connection_details.get("received_bytes"))) + "\n"
            response += "Total number of data bytes: " + str((connection_details.get("sent_bytes")) + (connection_details.get("received_bytes"))) + "\n"
        response += "END\n+++++++++++++++++++++++++++++++++"
        count+=1

    print(response)
    return None

def print_c(connection_dict):
    response = "c) General \n\n"
    closed = 0
    reset = 0
    open = 0 
    prior_connection = 0
 
    for connection in connection_dict:
        connection_details = connection_dict.get(connection)
        flags = connection_details.get("status")
        if flags[2] >= 1:
            reset += 1
        
        if flags[0] >= 1 and flags[1] >= 1: 
            closed += 1
        else:
            open += 1
        
        if not connection_details.get("in_order")[0].TCP_header.flags["SYN"] == 1: # Check if the first packet in the connection had SYN flag
            prior_connection += 1 

    response += "Total number of complete TCP connections: " + str(closed) + "\n"
    response += "Number of reset TCP connections: " + str(reset) + "\n"
    response += "Number of TCP connections that were still open when the trace capture ended: " + str(open) + "\n"
    response += "The number of TCP connections established before the capture started: " +str(prior_connection)
    print(response)

    return None

def print_d(connection_dict): 
    all_time_durations = []
    all_RTT = []
    all_packet_sizes = []
    all_window_sizes = []
    for connection in connection_dict:
        connection_details = connection_dict.get(connection)
        if connection_details.get("status")[0] >= 1 and connection_details.get("status")[1] >= 1:            
            all_time_durations.append(connection_details.get("duration")) # By connection
            # if connection_details.get("status")[2] == 0:
            all_packet_sizes.append(len(connection_details.get("forward")) + len(connection_details.get("backward")))# By connection
            all_window_sizes += [pck.TCP_header.window_size for pck in connection_details.get("in_order") if True]# By packet
            all_RTT +=  [pck.RTT_value for pck in connection_details.get("in_order") if pck.RTT_flag]# By packet

    
    response = "D) Complete TCP connections \n\n"
    response += "Minimum time duration: " + str(min(all_time_durations)) + " seconds\n"
    response += "Mean time duration: " + str(round(mean(all_time_durations),6)) +" seconds\n"
    response += "Maximum time duration: " + str(max(all_time_durations)) + " seconds\n\n"
    response += "Minimum RTT value: " + str(min(all_RTT)) + "\n"
    response += "Mean RTT value: " + str(round(mean(all_RTT),6)) +"\n"
    response += "Maximum RTT value " + str(max(all_RTT)) +"\n\n"
    response += "Minimum number of packets including both send/received: " + str(min(all_packet_sizes))+ "\n"
    response += "Mean number of packets including both send/received: " + str(round(mean(all_packet_sizes),6))+ "\n"
    response += "Maximum number of packets including both send/received: " + str(max(all_packet_sizes)) +"\n\n"
    response += "Minimum receive window size including both send/received: " + str(min(all_window_sizes)) + "\n"
    response += "Mean receive window size including both send/received: " + str(round(mean(all_window_sizes),6))+ " bytes\n"
    response += "Maximum receive window size including both send/received: " + str(max(all_window_sizes))+ " bytes\n"

    print(response)
    return None

# END OF QUESTION ANSWER FUNCTIONS
 
if __name__ == '__main__':

    if len(sys.argv) != 2:
        print("Usage: python3 WebTester.py '<.cap file>'")
        exit(1)   

    filename = sys.argv[1]
    packet_store = []
    
    f = open(filename, 'rb')
    # GET GLOBAL HEADER
    g_hdr = packetSplit.retrieve_global_header(f)
    packet_count = 1
    orig_time = 0
    byte_order = "<" if g_hdr.get_endianness() == "big" else ">"
    while True:
        # GET PACKET HEADER
        p_hdr = packetSplit.retrieve_packet_header(f, byte_order)
        if not p_hdr: # EOF
            break   

        # GET PACKET DATA
        packet_data = f.read(p_hdr.incl_len)

        # GET ETHERNET HEADER
        eth_hdr = packetSplit.retrieve_ethernet_header(packet_data)
        packet_data = packet_data[14:]

        # GET IPV4 HEADER
        ip_hdr = packetSplit.retrieve_ip_header(packet_data)   
        packet_data = packet_data[ip_hdr.ip_header_len:]
        if ip_hdr.protocol == 6: # Is TCP
            # GET TCP HEADER
            tcp_hdr = packetSplit.retrieve_tcp_header(packet_data)
            read_tcp_header = packet_data[tcp_hdr.data_offset*4:]
            if packet_count == 1:
                orig_time = p_hdr.ts_sec + p_hdr.ts_usec * 1e-6  
            # CREATE PACKET
            pck = packetSplit.generate_packet(ip_hdr, tcp_hdr, packet_count, p_hdr, orig_time, packet_data)
            packet_store.append(pck)
            packet_count += 1


    connectionSort.calculate_RTT(packet_store)
    f.close()


    # PRINTING ANSWERS
    connection_dict = connectionSort.sort_by_connection(packet_store)
    print_a(connection_dict)
    print("\n_______________________________________________________________________\n")
    print_b(connection_dict)
    print("\n_______________________________________________________________________\n")
    print_c(connection_dict)
    print("\n_______________________________________________________________________\n")
    print_d(connection_dict)
    print("\n_______________________________________________________________________\n")
    exit(0)
