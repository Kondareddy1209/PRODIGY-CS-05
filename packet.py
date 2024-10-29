from scapy.all import sniff, IP, TCP, UDP, Raw

def process_packet(packet):
    
    """
    Processes a captured network packet and prints relevant information.

    Parameters:
    packet (scapy.packet.Packet): The captured network packet.
    """
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source: {ip_layer.src} --> Destination: {ip_layer.dst}")

        # Check if the packet has a TCP layer
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Protocol: TCP | Source Port: {tcp_layer.sport} | Destination Port: {tcp_layer.dport}")

        # Check if the packet has a UDP layer
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"Protocol: UDP | Source Port: {udp_layer.sport} | Destination Port: {udp_layer.dport}")

        # Check if the packet has a Raw layer (payload)
        if Raw in packet:
            raw_data = packet[Raw].load
            print(f"Payload: {raw_data}")

        print("-" * 50)

def start_sniffer():
    """
    Starts the packet sniffer and calls the process_packet function for each captured packet.
    """
    print("Starting packet sniffer... Press Ctrl+C to stop.")
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    """
    Entry point of the script.
    Calls the start_sniffer function to begin capturing and processing network packets.
    """
    start_sniffer()