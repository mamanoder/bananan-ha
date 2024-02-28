# communication.py
import pickle
import socket
import threading
import scapy.all as scapy
# from checking_scripts.trafic import listen_to_ip_or_port
import time
import random
from config import Server_IP, PORT

try:
    # Get the local hostname
    hostname = socket.gethostname()

    # Get the IP address associated with the hostname
    ip_address = socket.gethostbyname(hostname)
except Exception as e:
    print(f"An error occurred: {e}")
print(f"Server IP: {Server_IP}")
SERVER_PORT = 8888
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((Server_IP, SERVER_PORT))


def check(traffic):
    print("got in")
    data = {"type": "check", "content": traffic}
    print(data)
    client_socket.send(pickle.dumps(data))


def message(message_content):
    data = {"type": "message", "content": message_content}
    client_socket.send(pickle.dumps(data))

def to_scan():
    data = {"type": "start_scan"}
    print(data)
    client_socket.send(pickle.dumps(data))

def PORT(port):
    data = {"type": "port", "number": port}
    print(data)
    client_socket.send(pickle.dumps(data))


def send_traffic(traffic):
    data = {"type": "check", "content": traffic}
    client_socket.send(pickle.dumps(data))


def receive_response():
    while True:
        data = client_socket.recv(3000)
        if data:
            try:
                data = pickle.loads(data)
            except pickle.UnpicklingError:
                data.decode()
            print(f"Received: {data}")
        if data["type"] == "port" and data["answar"] == False:
            port = data["number"]
            threading.Thread(target=listen_to_ip_or_port, args=(port, None)).start()

###########################################################################################just for now!
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
                threading.Thread(target=check, args=(packet_summary, )).start()
                # check(packet_summary)
                # Increment the packet count
                packet_count += 1
                # packet_callback.processed = True

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
threading.Thread(target=receive_response).start()

if __name__ == "__main__":
    listen_to_ip_or_port(port = 80)
    # while True:
    #     pass