import pyshark
import ipapi
import socket
import os 

tos = """
By using this script, you agree that you will use it solely for educational purposes. 
- You understand that you are solely responsible for any actions you take using this script, and that the creator of this script cannot be held responsible for any consequences that may arise from your use of it. 
- Use at your own risk.
"""
print(tos)

agree = input("Continue? [y/n]: ")

if agree.lower() != "y":
    exit()

if os.name == "nt": #Binbows
    os.system("cls")
else: # Linux
    os.system("clear")

# Get the local IP address
local_ip = socket.gethostbyname(socket.gethostname())

# Create a pyshark capture object
print("Creating capture object")
capture = pyshark.LiveCapture(interface='#YOUR INTERFACE HERE')

print("Sniffing packets...")

destination_ips = set()

# Loop through the packets in the capture
for packet in capture.sniff_continuously():
    # Ignore other packets that aren't UDP
    if packet.transport_layer != "UDP":
        continue
    
    if "CLASSICSTUN Layer" in str(packet.layers):
        #print(f"Got CLASSICSTUN packet")

        # Ignore the packet, if it's in the list.
        if packet.ip.src in destination_ips or packet.ip.dst in destination_ips:
            continue
        else:
            # Add the destination IP to the set
            print("Adding IP to ignore list")
            destination_ips.add(packet.ip.dst)

            # Resolve the location of the source and destination IPs
            src_location = ipapi.location(ip=packet.ip.src)
            dst_location = ipapi.location(ip=packet.ip.dst)

            # Check if the source or destination IP belongs to the "VALVE-CORPORATION" organization
            # This doesn't seem to work as theres no org sometimes...?
            # if src_location["org"] != "VALVE-CORPORATION" or dst_location["org"] != "VALVE-CORPORATION":

            # Print the IP address, location, city, and region of the source and destination
            if packet.ip.src == local_ip:
                print(f'Source: {packet.ip.src} (You)')
            else:
                print(f'Source: {packet.ip.src}')
            if 'country_name' in src_location:
                print(f'Location: {src_location["country_name"]}, {src_location["city"]}, {src_location["region"]}')
            else:
                print(f'Location: Unknown')

            print(f'Destination: {packet.ip.dst}')
            if 'country_name' in dst_location:
                print(f'Location: {dst_location["country_name"]}, {dst_location["city"]}, {dst_location["region"]}')
            else:
                print(f'Location: Unknown')

            # Calculate the length of the longest string of text
            max_length = max(len(packet.ip.src), len(packet.ip.dst))
            if 'country_name' in src_location:
                max_length = max(max_length, len(src_location['country_name']), len(src_location['city']), len(src_location['region']))
            if 'country_name' in dst_location:
                max_length = max(max_length, len(dst_location['country_name']), len(dst_location['city']), len(dst_location['region']))

            # Print a separator line
            print('-' * max_length)
            print()
