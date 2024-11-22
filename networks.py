from scapy.all import *
import logging
from datetime import datetime
import os
import platform
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
import psutil
import time
import concurrent.futures
import signal

tcp_size = 0
udp_size = 0
ethernet_size = 0
throuput_tcp = 0
throuput_udp =0
throuput_ehternet = 0

sniff_running = True
last_calculation_time = time.time()
latency_data = {}

#task 1 and 2
#Fadi Azahrani, Ahmed Ammar, Faris Alghamdi, Abdulaziz Alasmari , Abdullah alkhiry 
def setup_logging():
    logging.basicConfig(
        filename='network_events.log',
        level=logging.INFO,
        format='%(message)s'
    )
    
def signal_handler(sig, frame):
    print("\nStopping capture...")
    sniff_running = False

# register the signal handler
signal.signal(signal.SIGINT, signal_handler)

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
    global latency_data

    # Ethernet Layer
    if Ether in packet:
        log_entries.append(f"[{timestamp}] Ethernet | Dest MAC: {packet[Ether].dst} | Source IP: {packet[Ether].src} | Size: {len(packet)} bytes")
    # IP Layer
    if IP in packet:
        proto = packet[IP].proto
        protocol_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(proto, str(proto))
        log_entries.append(f"[{timestamp}] IP | Protocol: {protocol_name} | Dest IP: {packet[IP].dst} | Source IP: {packet[IP].src} | Size: {len(packet)} bytes")
        conn_key = (packet[IP].dst, packet[IP].src)
        if conn_key not in latency_data: 
            latency_data[conn_key] = {"start": timestamp}
            #print(latency_data)
        else:
            latency_data[conn_key]["end"] = timestamp

    # TCP Layer
    if TCP in packet:
        flags = get_tcp_flags(packet[TCP])
        log_entries.append(
            f"[{timestamp}] TCP | Dest Port: {packet[TCP].dport}"
            f"| Source port: {packet[TCP].sport} Size: {len(packet)} bytes | Flags: {flags}"
        )
        # conn_key = (packet[TCP].dst, packet[TCP].src)
        # if conn_key not in latency_data: 
        #     latency_data[conn_key] = {"start": timestamp}
        # else:
        #     latency_data[conn_key]["end"] = timestamp

    # UDP Layer
    if UDP in packet:
        log_entries.append(
            f"[{timestamp}] UDP | Dest Port: {packet[UDP].dport} "
            f"| Source port: {packet[UDP].sport} Size: {len(packet)} bytes"
        )
        # conn_key = (packet[IP].dst, packet[IP].src)
        # print(conn_key)
        # if conn_key not in latency_data: 
        #     latency_data[conn_key] = {"start": timestamp}
        # else:
        #     latency_data[conn_key]["end"] = timestamp

    # Log all entries
    for entry in log_entries:
        logging.info(entry)

def start_capture(interface=None, filter=""):
    global sniff_running
    if platform.system() == "Windows":
        if interface is None:
            interface = get_network_interface_name('ethernet')
    else:
        interface = "enp0s31f6"  # Default for Linux
    setup_logging()
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        throughput_future = executor.submit(calculate_throughput)
        try:
            # Start packet sniffing
            sniff_running = True
            
            sniff(iface=interface, filter=filter, prn=packet_callback, store=0, 
                  stop_filter=lambda x: not sniff_running)
        except KeyboardInterrupt:
            print("\nStopping capture...")
            sniff_running = False
        finally:
            sniff_running = False
            throughput_future.result()


#task 3
def calculate_throughput():
    global tcp_size, udp_size, ethernet_size, last_calculation_time, sniff_running
    file_position = 0
    while sniff_running:
        time.sleep(3)  # Wait for 10 seconds
        current_time = time.time()
        interval = current_time - last_calculation_time
        with open('network_events.log', 'r') as f:
        
            f.seek(file_position)
            for line in f:
                if 'TCP' in line and 'Protocol' not in line:
                    tcp_size += int(line.split('Size:')[1].split('bytes')[0].strip())
                elif 'UDP' in line and 'Protocol' not in line:
                    num = int(line.split('Size:')[1].split('bytes')[0].strip())
                    udp_size += num
                elif 'Ethernet' in line and 'Protocol' not in line:
                    ethernet_size += int(line.split('Size:')[1].split('bytes')[0].strip())
                    #print(ethernet_size)
            file_position = f.tell()
        # Calculate throughputs
        tcp_throughput = (tcp_size * 8) / interval if interval > 0 else 0
        udp_throughput = (udp_size * 8) / interval if interval > 0 else 0
        ethernet_throughput = (ethernet_size * 8) / interval if interval > 0 else 0
        
        print(f"\nThroughput Statistics (bits per second):")
        print(f"TCP Throughput: {tcp_throughput:.2f} bps")
        print(f"UDP Throughput: {udp_throughput:.2f} bps")
        print(f"Ethernet Throughput: {ethernet_throughput:.2f} bps")
        
        # Reset counters and update last calculation time
        tcp_size = 0
        udp_size = 0
        ethernet_size = 0
        last_calculation_time = current_time

def calculate_latency_data():
    total_latency = 0
    count = 0
    for conn_key, times in latency_data.item():
        if "start" in times and "end" in times:
            total_latency += (times["end"] - times["start"]) * 1000
            count += 1
            avg_latency = total_latency / count if count > 0 else 0
            print(f"\nAverage Latency: {avg_latency:.2f} ms")

        

if __name__ == "__main__":
    try:
        # Start capturing on default interface
        start_capture()
        calculate_latency_data()
        
    except KeyboardInterrupt:
        print("\nCapture stopped by user")
        sniff_running = False
        
    except PermissionError:
        print("Error: Run with administrator privileges to capture packets")




#task 4 snippet

# Initialize data structures for tracking throughput and latency
throughput_data = defaultdict(int)  # Track total bytes per protocol
latency_data = {}  # Track timestamps for latency calculation
exit_flag = threading.Event()

# Update event data and throughput
def update_event_data(protocol, src_addr, dest_addr, message_size, timestamp):
    event_data[protocol].append(message_size)
    throughput_data[protocol] += message_size  # Track bytes for throughput
    if protocol == "Ethernet":
        unique_macs.add(src_addr)
    else:
        unique_ips.add(src_addr)
    # Track latency for TCP/UDP
    if protocol in ["TCP", "UDP"]:
        conn_key = (src_addr, dest_addr)
        if conn_key not in latency_data:
            latency_data[conn_key] = {"start": timestamp}
        else:
            latency_data[conn_key]["end"] = timestamp

# # Calculate throughput every 10 seconds
# def calculate_throughput(interval=10):
#     print("\n--- Throughput (bps) ---")
#     for protocol, bytes_count in throughput_data.items():
#         throughput_bps = (bytes_count * 8) / interval
#         print(f"{protocol}: {throughput_bps:.2f} bps")
#         throughput_data[protocol] = 0  # Reset counter after each calculation

# Calculate average latency
def calculate_latency():
    total_latency = 0
    count = 0
    for conn_key, times in latency_data.items():
        if "start" in times and "end" in times:
            latency = (times["end"] - times["start"]) * 1000  # in ms
            total_latency += latency
            count += 1
    avg_latency = total_latency / count if count > 0 else 0
    print(f"\nAverage Latency: {avg_latency:.2f} ms") 