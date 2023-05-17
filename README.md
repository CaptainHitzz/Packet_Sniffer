## Packet Sniffer
This project is a packet sniffer and analyzer implemented in Python using the Scapy library. The script allows users to select a network interface from the available options on their system and captures packets flowing through that interface. It analyzes the captured packets to identify HTTP requests and potential login information. Whenever an HTTP request is detected, the script extracts the URL and prints it as an HTTP request. It also checks if the packet payload contains keywords related to login information and, if found, prints a message indicating possible username/password. Additionally, the script logs the captured packets to a file for further analysis. The project aims to provide a simple yet effective way to capture and analyze network packets, making it a valuable tool for network security and troubleshooting tasks.

### Working of Code:
1. The script begins by importing the necessary modules and libraries, including platform, scapy, http from scapy.layers, and netifaces.

2. The get_interface() function is defined. It uses netifaces to retrieve the available network interfaces on the system. It displays a list of interfaces and prompts the user to choose an interface by entering the corresponding number.

3. The sniff_packets(interface) function is defined. It takes the selected interface as an argument and starts packet capturing using scapy.sniff(). It sets the iface parameter to the selected interface, disables storing packets in memory (store=False), and specifies the callback function analyze_packet to process each captured packet.

4. The analyze_packet(packet) function is defined. It is the callback function called for each captured packet. It analyzes the packet contents and performs various checks.

5. Inside analyze_packet(packet), it first checks if the packet has an HTTP request layer (packet.haslayer(http.HTTPRequest)). If so, it extracts the URL using the get_url(packet) function and prints it as an HTTP request.

6. It then checks if the packet has a raw layer (packet.haslayer(scapy.Raw)) and extracts the payload using the get_payload(packet) function. If the payload contains specific keywords related to login information, it prints a message indicating possible username/password.

7. After analyzing the packet, it calls the log_packet(packet) function to log the packet information to a file named "packet_log.txt".

8. The get_url(packet) function extracts the URL from the HTTP request by accessing the Host and Path fields of the http.HTTPRequest layer.

9. The get_login_info(packet) function checks if the packet's raw payload contains keywords related to login information. If found, it returns the payload.

10. The get_payload(packet) function checks if the packet has a raw layer and returns the payload as a decoded string.

11. The log_packet(packet) function appends a summary of the packet to the "packet_log.txt" file.

12. The code then checks the current platform using platform.system(). If it is Windows, it uses the Windows-specific method get_windows_if_list() from scapy.arch.windows to retrieve network interfaces. Otherwise, it uses netifaces to retrieve network interfaces on non-Windows systems.

13. It displays the detected network interfaces and prompts the user to choose the interface to sniff packets on.

14. The selected interface is then passed to the sniff_packets(interface) function to start capturing packets.
