import socket
import struct
import os

# Firewall Rules
rules = [
    {"action": "allow", "protocol": "tcp", "port": 80},
    {"action": "allow", "protocol": "tcp", "port": 443},
    {"action": "block", "protocol": "tcp", "port": 22},
]

# Function to Apply Rules
def apply_rules(packet):
    ip_header = packet[0:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    protocol = iph[6]

    if protocol == 6:  # TCP
        tcp_header = packet[20:40]
        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
        source_port = tcph[0]
        dest_port = tcph[1]

        for rule in rules:
            if rule["protocol"] == "tcp" and rule["port"] == dest_port:
                if rule["action"] == "block":
                    return False
    return True

# Function to Capture Packets
def capture_packets():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    while True:
        packet, addr = s.recvfrom(65565)
        if apply_rules(packet):
            print(f"Packet allowed from {addr}")
        else:
            print(f"Packet blocked from {addr}")

if __name__ == "__main__":
    capture_packets()
