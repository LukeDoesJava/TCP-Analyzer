from statistics import mean
from struct import *
from packet_struct import *

# START OF CONNECTION SORTING FUNCTIONS
def flag_update(flags, pck):
    if pck.TCP_header.flags["SYN"] == 1:
        flags[0] += 1
    elif pck.TCP_header.flags["FIN"] == 1:
        flags[1] += 1
    elif pck.TCP_header.flags["RST"] == 1:
        flags[2] += 1

    return flags

def sort_by_connection(packet_store):
    # DATA STRUCTURE IS AS FOLLOWS:
    # {
    #     connection1: 
    #         {
    #             "in_order": [packet1, packet2, packet3, ...],
    #             "forward": [packet1, packet2, packet3, ...],
    #             "backward": [packet1, packet2, packet3, ...],
    #             "packet_amount": 0,
    #             "start": 0.0,
    #             "end": 0.0,
    #             "sent_bytes": 0,
    #             "received_bytes": 0,
    #             "status": [0, 0, 0], # Let this represent the values of the flags S, F, /R
    #             "duration": 0.0
    #         },
    #     etc....
    # }
    # Structure assumes the first connection found from peer 1 to peer 2 as "forward" and the reverse as "backward"
    connection_lib = {}
    is_terminated_gracefully = False
    for pck in packet_store:
        fwd_connection = (pck.IP_header.src_ip, pck.TCP_header.src_port, pck.IP_header.dst_ip, pck.TCP_header.dst_port)
        bwd_connection = (pck.IP_header.dst_ip, pck.TCP_header.dst_port, pck.IP_header.src_ip, pck.TCP_header.src_port)
        pck_byte_payload = pck.IP_header.total_len -  pck.IP_header.ip_header_len - pck.TCP_header.data_offset #Why does it not work with included eth header?
        # CASE 1: Connection already exists as is
        if connection_lib.get(fwd_connection):
            connection_lib.get(fwd_connection).get("in_order").append(pck)
            connection_lib.get(fwd_connection).get("forward").append(pck)
            if pck.TCP_header.flags["FIN"] == 1 and pck.TCP_header.flags["ACK"] == 1:
                connection_lib[fwd_connection]["end"] = pck.timestamp
                is_terminated_gracefully = True
            elif not is_terminated_gracefully:
                connection_lib[fwd_connection]["end"] = pck.timestamp
            connection_lib[fwd_connection]["sent_bytes"] += pck_byte_payload 
            connection_lib[fwd_connection]["status"] = flag_update(connection_lib[fwd_connection].get("status"), pck)
            connection_lib[fwd_connection]["packet_amount"] += 1
            connection_lib[fwd_connection]["duration"] = round(connection_lib[fwd_connection]["end"] - connection_lib[fwd_connection]["start"], 6)


        # Case 2: Connection exists but in reverse
        elif connection_lib.get(bwd_connection):
            connection_lib.get(bwd_connection).get("in_order").append(pck)
            connection_lib.get(bwd_connection).get("backward").append(pck)
                    # Check for termination (FIN, ACK) and update accordingly
            if pck.TCP_header.flags["FIN"] == 1 and pck.TCP_header.flags["ACK"] == 1:
                connection_lib[bwd_connection]["end"] = pck.timestamp
                is_terminated_gracefully = True  # Same logic for reverse direction
            
            # Only update end time if it hasn't been terminated gracefully
            elif not is_terminated_gracefully:
                connection_lib[bwd_connection]["end"] = pck.timestamp
            connection_lib[bwd_connection]["received_bytes"] += pck_byte_payload 
            connection_lib[bwd_connection]["status"] = flag_update(connection_lib[bwd_connection].get("status"), pck)
            connection_lib[bwd_connection]["packet_amount"] += 1
            connection_lib[bwd_connection]["duration"] = round(connection_lib[bwd_connection]["end"] - connection_lib[bwd_connection]["start"], 6)
            
        # Case 3: Connection does not exist
        else:
            connection_lib[fwd_connection] = {
                "in_order": [pck],
                "forward": [pck],
                "backward": [],
                "packet_amount": 1,
                "start": pck.timestamp,
                "end": 0,
                "sent_bytes": pck_byte_payload,
                "received_bytes": 0,
                "status" : flag_update([0,0,0], pck), # Let this represent the values of the flags S, F, /R
                "duration": 0
            }

            # Update flags

        
    return connection_lib

def calculate_RTT(packet_store):
    client_ip = packet_store[0].IP_header.src_ip
    for i in range(len(packet_store)-1):
        pck = packet_store[i]
        has_control_flags = pck.TCP_header.flags["SYN"] == 1 or pck.TCP_header.flags["FIN"] == 1
        if pck.IP_header.src_ip == client_ip and pck.TCP_header.flags["RST"] == 0 and has_control_flags:
            expected_seq = pck.TCP_header.seq_num + 1 
            for j in range(i + 1, len(packet_store)):
                response_pck = packet_store[j]
                if (response_pck.IP_header.dst_ip == client_ip and response_pck.TCP_header.ack_num == expected_seq):
                    pck.RTT_value = round(response_pck.timestamp - pck.timestamp, 6)
                    pck.RTT_flag = True
                    break
    return
# END OF CONNECTION SORTING FUNCTIONS