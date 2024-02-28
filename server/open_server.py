import socket
import threading
import server_GUI
from config import Server_IP, PORT
# try:
#     # Get the local hostname
#     hostname = socket.gethostname()
#
#     # Get the Server_IP address associated with the hostname
#     ip_address = socket.gethostbyname(hostname)
#     Server_IP = ip_address
#     Server_IP = "172.20.135.77"
#     print(Server_IP)
#
# except Exception as e:
#     print(f"An error occurred: {e}")

# PORT = 8888

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((Server_IP, PORT))

server.listen()
print(f"[*] Listening on {Server_IP}:{PORT}")

client_sockets = set()
