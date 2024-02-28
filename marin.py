import os
import platform
import threading
import subprocess
import time


def start_server():
    print("Starting server...")
    server_process = subprocess.Popen(
        ["python", "main_server.py", "checking_if_port_sus.py"],
        cwd=os.path.join("server"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    print(os.path.join("server"))


    def start_website():
        print("Starting the site...")
        server_process = subprocess.Popen(
            ["python", "panel.py"],
            cwd=os.path.join("server", "website"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # Capture and print the output
        out, err = server_process.communicate()
        print(out.decode())
        print(err.decode())


    def start_client():
        # Wait for the server to start before starting the client
        time.sleep(2)

        print("Starting client...")
        client_process = subprocess.Popen(
            ["python", "server_communication.py", "portscan.py", "config.py"],
            cwd=os.path.join("client"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NEW_CONSOLE if platform.system() == 'Windows' else 0
        )

        # Capture and print the output
        out, err = client_process.communicate()
        print(out.decode())
        print(err.decode())


    if __name__ == "__main__":
        server_thread = threading.Thread(target=start_server)
        website_thread = threading.Thread(target=start_website)
        client_thread = threading.Thread(target=start_client)

        # Start the threads
        server_thread.start()
        website_thread.start()
        time.sleep(2)
        client_thread.start()

        # Wait for the threads to finish before allowing the main thread to exit
        server_thread.join()
        client_thread.join()
