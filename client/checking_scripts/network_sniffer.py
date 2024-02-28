import subprocess
import os
import urllib.request
import zipfile
from pathlib import Path

def find_tshark_path():
    # Add the path to your Wireshark installation directory
    wireshark_path = "C:\\Program Files\\Wireshark"

    # Check if tshark.exe exists in the specified path
    tshark_path = os.path.join(wireshark_path, "tshark.exe")
    if os.path.exists(tshark_path):
        return tshark_path
    else:
        return None

def download_and_install_wireshark():
    # Specify the download URL for the Wireshark repository ZIP file
    wireshark_zip_url = "https://2.na.dl.wireshark.org/win64/Wireshark-4.2.2-x64.exe"

    # Specify the path to download and save the ZIP file
    zip_file_path = Path("C:\\Program Files\\Wireshark")

    # Download the Wireshark repository ZIP file
    print("Downloading Wireshark from GitHub...")
    urllib.request.urlretrieve(wireshark_zip_url, zip_file_path)

    # Specify the path to extract the contents
    extract_path = Path("C:\\Program Files\\Wireshark")

    # Extract the contents of the ZIP file
    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        zip_ref.extractall(extract_path)

    # Rename the extracted folder to the desired installation path
    extracted_folder = zip_ref.namelist()[0]
    extracted_path = extract_path / extracted_folder
    installation_path = extract_path / "wireshark"

    extracted_path.rename(installation_path)

    # Delete the ZIP file after extraction
    zip_file_path.unlink()

def check_wireshark():
    tshark_path = find_tshark_path()

    if tshark_path:
        try:
            # Specify the full path to the Tshark executable
            subprocess.run([tshark_path, "--version"], check=True)
            print("Wireshark found.")
        except subprocess.CalledProcessError:
            print("Wireshark not found.")
            download_and_install_wireshark()
    else:
        print("Wireshark not found. Unable to capture packets.")
        download_and_install_wireshark()

def capture_packets():
    tshark_path = find_tshark_path()

    if tshark_path:
        # Capture packets using tshark
        subprocess.run([tshark_path, "-i", "Ethernet", "-c", "5"])
    else:
        print("Wireshark not found. Unable to capture packets.")

if __name__ == "__main__":
    # Check if Wireshark is installed
    check_wireshark()

    # Capture network packets
    capture_packets()
