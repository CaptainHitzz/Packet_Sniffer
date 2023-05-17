#!/usr/bin/env python

import platform
import scapy.all as scapy
from scapy.layers import http
import netifaces

def get_interface():
    interfaces = netifaces.interfaces()
    print("Available network interfaces:")
    for i, interface in enumerate(interfaces):
        print(f"{i+1}. {interface}")

    while True:
        choice = input("Enter the number of the interface you want to sniff packets on: ")
        try:
            choice = int(choice)
            if 1 <= choice <= len(interfaces):
                return interfaces[choice - 1]
            else:
                print("Invalid choice. Please enter a valid interface number.")
        except ValueError:
            print("Invalid input. Please enter a valid interface number.")

def sniff_packets(interface):
    print(f"[*] Starting packet capture on {interface}...")
    scapy.sniff(iface=interface, store=False, prn=analyze_packet)

def analyze_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print(f"[+] HTTP Request >> {url}")

        login_info = get_login_info(packet)
        if login_info:
            print(f"\n\n[+] Possible username/password >> {login_info}\n\n")

    payload = get_payload(packet)
    if payload:
        if "login" in payload.lower():
            print("Login detected!")
        elif "malware" in payload.lower():
            print("Malware detected!")
        elif "attack" in payload.lower():
            print("Attack detected!")

    log_packet(packet)

def get_url(packet):
    url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    return url.decode()

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load.decode()
        keywords = ["username", "user", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in load.lower():
                return load

def get_payload(packet):
    if packet.haslayer(scapy.Raw):
        return packet[scapy.Raw].load.decode()

def log_packet(packet):
    with open("packet_log.txt", "a") as f:
        f.write(str(packet.summary()) + "\n")

# Check if the current platform is Windows
if platform.system() == "Windows":
    # Use the Windows-specific method to retrieve network interfaces
    from scapy.arch.windows import get_windows_if_list
    interfaces = get_windows_if_list()
else:
    # Use netifaces to retrieve network interfaces on non-Windows systems
    interfaces = netifaces.interfaces()

# Prompt the user to choose the network interface
print("Detected network interfaces:")
for i, interface in enumerate(interfaces):
    print(f"{i+1}. {interface}")

while True:
    choice = input("Enter the number of the interface you want to sniff packets on: ")
    try:
        choice = int(choice)
        if 1 <= choice <= len(interfaces):
            selected_interface= interfaces[choice - 1]
            break
        else:
          print("Invalid choice. Please enter a valid interface number.")
    except ValueError:
      print("Invalid input. Please enter a valid interface number.")  

sniff_packets(selected_interface)
