import socket
import threading
import pickle
import queue
from scapy.layers.inet import TCP
import checking_if_port_sus
from checking_network import handle_packet_summary
from open_server import *
from scapy.all import *
from checking_if_port_sus import check_port_sus
from server_GUI import start_gui_in_thread as GUI, send_message_to_chat as GUI_message




def send_message_to_chat_window(message):
    server_GUI.chat_window.display_message(message)



# Start capturing packets in a separate thread


def return_command(Type, port):
    print(port)
    print(Type)
    answear = check_port_sus(port)
    data = {"type": Type, "number": port, "answar": answear}
    print(data)
    try:
        client_socket.send(pickle.dumps(data))
    except Exception as e:
        print(f"Error sending data to client: {e}")
        # Optionally, you may want to close the client socket or take other appropriate actions

open_ports = set()


def packet_callback(packet,client_ip):
    open_ports = set()
    for port in range(1, 1025):  # Scanning common ports from 1 to 1024
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)  # Timeout for connection attempt
                result = s.connect_ex((client_ip, port))
                if result == 0:  # If connection successful
                    open_ports.add(port)
                    print("Port {} is open on {}".format(port, client_ip))
                    # Call a function to handle this open port
                    return_command("port", port=format(port))
        except socket.error:
            pass

def start_the_scan(client_ip):
    try:
        sniff(prn=packet_callback, store=0, args = (client_ip,))

        # Print open ports
        print("Open ports detected:")
        for port in open_ports:
            print("Port:", port)
            # check_ports = threading.Thread(target=return_command, args=("port", port))
            # check_ports.run()
    except Exception as e:
        print(f"Error")







def handle_client(client_socket, address):
    ports = queue.Queue()
    client_ip = address[0]
    while True:
        try:
            data = client_socket.recv(3000)
            if not data:
                break

            # Assuming the data is received in chunks, keep collecting until a complete object is received
            complete_data = b""
            while True:
                complete_data += data
                try:
                    # Try to unpickle the data
                    decoded_data = pickle.loads(complete_data)
                    break  # Break the inner loop if successful
                except pickle.UnpicklingError:
                    # If not successful, continue receiving data
                    data = client_socket.recv(3000)
                    if not data:
                        break  # Break the inner loop if no more data is received

            if not decoded_data:
                break  # Break the outer loop if no more data is received

            # Handle the decoded data as needed
            if decoded_data["type"] == "message":
                message = decoded_data["content"]
                print(f"[{address}] Message: {message}")
                data = {"type": "answear", "answear": "answear"}
                # print(data)
                client_socket.send(pickle.dumps(data))

            elif decoded_data["type"] == "check":
                print(decoded_data)
                print("sended")
                traffic = decoded_data["content"]
                print(traffic)
                check_trafic = threading.Thread(target=handle_packet_summary, args=(traffic,))
                check_trafic.run()

            elif decoded_data["type"] == "start_scan":
                check_ports = threading.Thread(target=start_the_scan, args=(client_ip, )).start()

            elif decoded_data["type"] == "port" or decoded_data["type"] == "port+":
                # Handle port-related data
                port = decoded_data["number"]
                ports.put(port)

                print(f"Port: {port} is open")
                # answer = input("True or False?").encode()
                sug = "port"
                check_ports = threading.Thread(target=return_command, args=(sug, port))
                check_ports.run()
                print("success")


        except Exception as e:
            print(f"Error handling client {address}: {e}")
            break


    print(f"[*] Client {address} disconnected")
    client_sockets.remove(client_socket)
    client_socket.close()

# GUI()
# threading.Thread(target=GUI).start()
while True:
    try:
        client_socket, address = server.accept()
        print(f"[*] Connected to {address}")
        # GUI_message("server", f"[*] Connected to {address}")
        client_sockets.add(client_socket)
        threading.Thread(target=handle_client, args=(client_socket, address)).start()
        # check_ports = threading.Thread(target=return_command, args=(sug, port))
        # check_ports.run()
    except Exception as e:
        print(f"Error handling client {address}: {e}")

# threading.Thread(target=GUI).start()

