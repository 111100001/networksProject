from scapy.all import *
import logging
from datetime import datetime
import os
import platform
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
import psutil
import keyboard
import threading
import time


tcp_size = 0
udp_size = 0
ethernet_size = 0
throuput_tcp = 0
throuput_udp =0
throuput_ehternet = 0

#task 1 and 2
#Fadi Azahrani, Ahmed Ammar, Faris Alghamdi, Abdulaziz Alasmari , Abdullah alkhiry
def setup_logging():
    logging.basicConfig(
        filename='network_events.log',
        level=logging.INFO,
        format='%(message)s'
    )


def get_network_interface_name(interface_type):
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == 2:  # AF_INET (IPv4)
                if interface_type.lower() == 'wifi' and 'wireless' in interface.lower():
                    return interface
                elif interface_type.lower() == 'ethernet' and 'ethernet' in interface.lower():
                    return interface
    return None


def get_tcp_flags(tcp_packet):
    flags = []
    if tcp_packet.flags.F: flags.append('FIN')
    if tcp_packet.flags.S: flags.append('SYN')
    if tcp_packet.flags.R: flags.append('RST')
    if tcp_packet.flags.P: flags.append('PSH')
    if tcp_packet.flags.A: flags.append('ACK')
    if tcp_packet.flags.U: flags.append('URG')
    return ' '.join(flags)


def packet_callback(packet):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
    log_entries = []

    # Ethernet Layer
    if Ether in packet:
        log_entries.append(f"[{timestamp}] Ethernet | Dest MAC: {packet[Ether].dst}")
    # IP Layer
    if IP in packet:
        proto = packet[IP].proto
        protocol_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(proto, str(proto))
        log_entries.append(f"[{timestamp}] IP | Protocol: {protocol_name} | Dest IP: {packet[IP].dst}")

    # TCP Layer
    if TCP in packet:
        flags = get_tcp_flags(packet[TCP])
        log_entries.append(
            f"[{timestamp}] TCP | Dest Port: {packet[TCP].dport} | "
            f"Size: {len(packet)} bytes | Flags: {flags}"
        )

    # UDP Layer
    if UDP in packet:
        log_entries.append(
            f"[{timestamp}] UDP | Dest Port: {packet[UDP].dport} | "
            f"Size: {len(packet)} bytes"
        )

    # Log all entries
    for entry in log_entries:
        logging.info(entry)

def sniff_packets(interface, filter):
    global sniff_running
    sniff(iface=interface, filter=filter, prn=packet_callback, store=0, stop_filter=lambda x: not sniff_running)

def start_capture(interface=None, filter=""):
    """
    Start capturing packets on specified interface
    Args:
        interface: Network interface to capture on (if None, will auto-detect)
        filter: BPF filter string
    """
    if platform.system() == "Windows":
        if interface is None:
            interface = get_network_interface_name('ethernet')
    else:
        interface = "eth0"  # Default for Windows

    setup_logging()
    print(f"Starting capture on {interface}. Press q to stop.")
    start_time = time.perf_counter()
    sniff_thread = threading.Thread(target=sniff_packets, args=(interface, filter))
    global sniff_running
    sniff_thread.start()
    keyboard.wait('q')

    sniff_running = False
    end_time = time.perf_counter()
    print("Stopping capturing...")
    interval = end_time - start_time
    return interval


if __name__ == "__main__":
    try:
        # Start capturing on default interface
        interval = start_capture()
            
        #print(calculate_throuput_tcp(tcp_size, interval))
    except KeyboardInterrupt:
        print("\nCapture stopped by user")
    except PermissionError:
        print("Error: Run with administrator privileges to capture packets")


#task 3

def calculate_sizes(log_file):
    
    with open(log_file, 'r') as f:
        for line in f:
            if 'TCP' in line and 'Protocol' not in line:
                print(line.split('|')[2].split(':')[1].strip(' bytes').strip())
                tcp_size += int(line.split('|')[2].split(':')[1].strip(' bytes').strip())
                print(tcp_size)
            elif 'UDP' in line and 'Protocol' not in line:
                udp_size += int(line.split('|')[2].split(':')[1].strip(' bytes').strip())
           # elif 'Ethernet' in line and 'Protocol' not in line:
               # ethernet_size += int(line.split('|')[1].split(':')[1].strip(' bytes').strip())

#calculate_sizes('network_events.log')

def calculate_throuput_tcp(protocol_tcp, interval):
    throuput_tcp = protocol_tcp * 8 / interval
    return throuput_tcp

def calculate_throuput_udp(protocol_udp, interval):
    throuput_udp = protocol_udp * 8 / interval
    return throuput_udp

def calculate_throuput_ethernet(protocol_ethernet, interval):
    throuput_ethernet = protocol_ethernet * 8 / interval
    return throuput_ethernet


