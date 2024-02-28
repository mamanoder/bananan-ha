import scapy.all as scapy

def listen_to_ip_or_port(port=None, ip=None, num_packets=50):
    target_ip = ip
    target_port = port
    packet_count = 0

    def packet_callback(packet):
        nonlocal packet_count

        ip_layer = packet.getlayer(scapy.IP)
        tcp_layer = packet.getlayer(scapy.TCP)

        if tcp_layer and ip_layer:
            # if (target_ip is None or ip_layer.dst == target_ip) and (target_port is None or tcp_layer.dport == target_port):
                # Summarize packet information into a dictionary
                raw = packet.getlayer(scapy.Raw)
                if raw:
                    data = bytes(raw)
                    packet_summary = {
                        "source_ip": ip_layer.src,
                        "destination_ip": ip_layer.dst,
                        "source_port": tcp_layer.sport,
                        "destination_port": tcp_layer.dport,
                        "protocol": "TCP",
                        "payload": str(packet.payload),
                        "data": data
                    }

                    # Print the packet summary
                    print(packet_summary)

                    # Increment the packet count
                    packet_count += 1

                    # Check if we have reached the specified number of packets
                    if num_packets is not None and packet_count >= num_packets:
                        raise KeyboardInterrupt  # Stop sniffing after reaching the desired number of packets

    try:
        # Start sniffing packets
        print("Starting packet sniffing...")
        if num_packets is None:
            scapy.sniff(prn=packet_callback, store=0)
        else:
            scapy.sniff(prn=packet_callback, store=0, count=num_packets)

    except KeyboardInterrupt:
        # Handle exit
        print("\nExiting...")


###########################################################################################just for now!
# threading.Thread(target=receive_response).start()

if __name__ == "__main__":
    listen_to_ip_or_port(port = 443)
    while True:
        pass