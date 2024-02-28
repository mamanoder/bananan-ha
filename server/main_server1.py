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

import tkinter as tk
from threading import Thread
from queue import Queue
from tkinter import Tk, Label, Button


class ChatWindow:
    def __init__(self, master):
        self.master = master

        master.title("Chat Window")
        master.geometry("400x300")

        self.message_frame = tk.Frame(master)
        self.message_frame.pack(fill=tk.BOTH, expand=True)

        self.messages_text = tk.Text(self.message_frame, bg="black", fg="white")
        self.messages_text.pack(fill=tk.BOTH, expand=True)

        self.input_frame = tk.Frame(master, bg="black")
        self.input_frame.pack(fill=tk.BOTH)

        self.input_entry = tk.Entry(self.input_frame, bg="black", fg="white")
        self.input_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.send_button = tk.Button(self.input_frame, text="Send", bg="black", fg="white", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT)

        # Start listening for messages
        #self.listen_for_messages()



    def send_message(self):
        message = self.input_entry.get()
        self.input_entry.delete(0, tk.END)
        self.display_message("You: " + message)

        # Put the message into the queue
        self.message_queue.put(message)

    def display_message(self, message):
        self.messages_text.insert(tk.END, message + "\n")
        self.messages_text.see(tk.END)  # Scroll to the end of the messages

    def listen_for_messages(self):
        # Continuously check for messages in the queue and display them
        while True:
            if not self.message_queue.empty():
                message = self.message_queue.get()
                self.display_message("Friend: " + message)



#message_queue = Queue()







# Create a message queue

# Start the GUI in a separate thread


# Function to send a message from other modules
#def send_message_to_chat(message, message_queue=message_queue):
 #   message_queue.put(message)




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



root = Tk()
my_gui = ChatWindow(root)
root.mainloop() #chatgpt     make this code work that after this line it will keep on running the the while and the gui will open so it will be like thread


# threading.Thread(target=GUI).start()
while True:
    try:
        print(f"after the threading")
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

