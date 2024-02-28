# Import necessary modules
import socket
import sys
import threading
import queue
from communication import *
import portscan  # Import directly from checking_scripts

# Define global variables
results = queue.Queue()

def get_local_ip():
    try:
        # Create a socket object and connect to an external server
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Connecting to Google's public DNS server
        local_ip = s.getsockname()[0]
        print(local_ip)
        s.close()
        return local_ip
    except socket.error as e:
        print(f"Error getting local IP: {e}")
        return None

def port_printer():
    num = 0
    while True:
        try:
            port = results.get(timeout=0.01)
            yield port
            num += 1
        except queue.Empty:
            continue
    yield -1

def get_in(port):
    is_GUI = False
    resultxt = None
    ip = get_local_ip()
    # Modify start_scan to return a value indicating success or failure
    scan_successful = portscan.start_scan(ip, port, is_GUI, resultxt)
    if not scan_successful:
        print("Server is down or unreachable.")
    else:
        print("Scan completed successfully.")
    # Continue with other actions or cleanup as needed

def check_port(port):
    print("got it")
    print(port)
    PORT(port)

while True:
    try:
        user_input = input("> ")
    except KeyboardInterrupt:
        print("Program interrupted. Exiting gracefully.")
        # Add any cleanup or exit code here if needed
        sys.exit(0)  # Optional: Exit the program with a clean exit code

    command = user_input.split(" ")[0]

    if command == "message":
        content = " ".join(user_input.split(" ")[1:])
        message(content)

    elif command == "port":
        print("aba")
        print("aba")
        tread1 = threading.Thread(target=to_scan).start()
        tread2 = threading.Thread(target=get_in, args=(SERVER_PORT, )).start()
        print(SERVER_PORT)
        print("amen")

    else:
        print("Invalid command")
