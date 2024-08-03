from scapy.all import rdpcap, IP, TCP, UDP, ICMP
import pandas as pd
import time
import os

# Define the file path
pcap_file_path = r'C:\predict-network-anomaly-new\predict-network-anomaly\1-training\SYN_ACK_FLOOD\pcap_files\win-normal.pcap'

# Check if the file exists
if not os.path.isfile(pcap_file_path):
    print(f"File not found: {pcap_file_path}")
else:
    print(f"File found: {pcap_file_path}")
    
    # Load the pcap file
    packets = rdpcap(pcap_file_path)

    # List to store packet details
    packet_details = []

    # Process packets to extract details
    for packet in packets:
        if IP in packet:
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(packet.time)))
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            length = len(packet)

            # Skip SYN flood and ACK flood packets
            if TCP in packet:
                if packet[TCP].flags & 0x02:  # SYN flag
                    continue
                if packet[TCP].flags & 0x10:  # ACK flag
                    continue
                protocol = 'TCP'
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                seq_num = packet[TCP].seq
                win_size = packet[TCP].window
                info = f"{src_port} > {dst_port} [{protocol}] Seq={seq_num} Win={win_size} Len={length}"
            elif UDP in packet:
                protocol = 'UDP'
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                seq_num = 0
                win_size = 0
                info = f"{src_port} > {dst_port} [{protocol}] Seq={seq_num} Win={win_size} Len={length}"
            else:
                continue

            severity = 0  # Since it is normal traffic
            packet_info = {
                "Info": info,
                "Severity": severity
            }
            packet_details.append(packet_info)

    # Convert to DataFrame
    df = pd.DataFrame(packet_details)

    # Save to a TSV file
    output_file_path = r'C:\predict-network-anomaly-new\predict-network-anomaly\1-training\SYN_ACK_FLOOD\pcap_files\normal_data_3.tsv'
    df.to_csv(output_file_path, sep='\t', index=False)

    print(f'Normal traffic information captured and saved to {output_file_path}')
