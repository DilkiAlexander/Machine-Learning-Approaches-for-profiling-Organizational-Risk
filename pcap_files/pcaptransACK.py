from scapy.all import rdpcap, TCP, IP
import pandas as pd
import time

# Load the pcap file
pcap_file_path = r'C:\predict-network-anomaly-new\predict-network-anomaly\1-training\Test_Data\ACK.pcap'  # Adjust the path as needed
packets = rdpcap(pcap_file_path)

# List to store ACK packet details
packet_details = []

# Process packets to extract ACK packet details
for packet in packets:
    if IP in packet and TCP in packet:
        # Check if the packet is an ACK packet (ACK flag set, SYN flag not set)
        if packet[TCP].flags == 0x10:  # ACK flag only
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(packet.time)))
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            seq_num = packet[TCP].seq
            ack_num = packet[TCP].ack
            win_size = packet[TCP].window
            packet_length = len(packet)
            info = f"{src_port} > {dst_port} [ACK] Seq={seq_num} Ack={ack_num} Win={win_size} Len={packet_length}"
            severity = 1
            packet_info = {
                "Info": info,
                "Severity": severity
            }
            packet_details.append(packet_info)

# Convert to DataFrame
df = pd.DataFrame(packet_details)

# Save to a TSV file
output_file_path = 'output_ack_flood_info.tsv'
df.to_csv(output_file_path, sep='\t', index=False)

print(f'ACK flood information captured and saved to {output_file_path}')
