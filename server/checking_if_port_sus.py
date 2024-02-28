from config import exceptional_ports
safe_ports = []

def check_port_sus(port):
    if is_whitelist(port) == True:
        return True
    else:

        return False

def is_whitelist(port):
    for port_list in safe_ports:
        if port == port_list:
            return True
        else:
            pass
    return False
