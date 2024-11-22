from scapy.all import sniff, IP, TCP, UDP, Ether
from collections import defaultdict
import threading
import time
import logging
import matplotlib.pyplot as plt
from datetime import datetime
import signal
import sys
from colorama import Fore, Back, Style

                                                # Set up logging configuration
logging.basicConfig(
    filename='network_events.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

class NetworkMonitor:

                                                #this is a constructor for the class
    def __init__(self):
        self.initialize_metrics()
        self.initialize_throughput_tracking()
        self.initialize_control_flags()
        self.start_monitoring_threads()

    def initialize_metrics(self):

                                                 #these are instance variables of the class   
        self.throughput_data = defaultdict(int)  # this is a custom dictionary that 
                                                 # automatically assigns a default value to any key 
                                                 # that does not exist in the dictionary when it is accessed
        self.latency_data = {}            # dictionary to store latency data for tcp and udp packets for chart
        self.packet_sizes = defaultdict(list)   # dictionary to store packet sizes for every packet, sets an empty list as the default value for each key that does not exist
        self.unique_ips = set()                 #this a set to store unique IP addresses
        self.unique_macs = set()                #this a set to store unique MAC addresses
        self.protocol_counts = defaultdict(int) # dictionary to store packet counts per protocol
        self.start_time = time.time()    # variable to store the start time of the monitoring process

    def initialize_throughput_tracking(self):
                                                #initialize throughput tracking data structures
                                                #this is a dictionary to store throughput data for each protocol for chart
        self.throughput_history = {
            'Ethernet': {'times': [], 'values': []},
            'TCP': {'times': [], 'values': []},
            'UDP': {'times': [], 'values': []}
        }
        self.latency_history = []          #list to store latency values for latency distribution chart

    def initialize_control_flags(self):  #this is a method to help with the control of the monitoring process
        self.exit_flag = threading.Event()

    def packet_callback(self, packet) :  #this is a method to process each packet captured
        """Process each captured packet"""
        timestamp = time.time()           #get the current time
        
                                                 # Process Ethernet layer
        if Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            self.unique_macs.add(src_mac)
            self.unique_macs.add(dst_mac)
            self.update_metrics("Ethernet", len(packet), src_mac, dst_mac, timestamp)

                                                # Process IP layer
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            self.unique_ips.add(src_ip)
            self.unique_ips.add(dst_ip)
            
                                                # Process TCP layer
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                self.update_metrics("TCP", len(packet), f"{src_ip}:{src_port}", 
                                  f"{dst_ip}:{dst_port}", timestamp)
                
                                                # Process UDP layer
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                self.update_metrics("UDP", len(packet), f"{src_ip}:{src_port}", 
                                  f"{dst_ip}:{dst_port}", timestamp)
                                                #this is a method to update the metrics for each packet captured
    def update_metrics(self, protocol, packet_size, src_addr, dst_addr, timestamp):
        """Update various network metrics"""
                                                # Update packet counts and sizes
        self.protocol_counts[protocol] += 1
        self.packet_sizes[protocol].append(packet_size)
        self.throughput_data[protocol] += packet_size
        
                                                # Log the event using the logging module
        log_message = (f"Protocol: {protocol}, Source: {src_addr}, "
                      f"Destination: {dst_addr}, Size: {packet_size} bytes")
        logging.info(log_message)
        
                                                # Track latency for TCP/UDP
        if protocol in ["TCP", "UDP"]:          #tuple to store the source and destination addresses
            conn_key = (src_addr, dst_addr)
                                                #if the addresses not in the latency data dictionary, add them
            if conn_key not in self.latency_data:
                self.latency_data[conn_key] = {"start": timestamp}
            else:
                if "start" in self.latency_data[conn_key]:
                    latency = (timestamp - self.latency_data[conn_key]["start"]) * 1000
                    self.latency_history.append(latency)
                    del self.latency_data[conn_key]

    def calculate_throughput(self):
        """Calculate and store throughput metrics"""
        while not self.exit_flag.is_set():
            time.sleep(10)  # Calculate every 10 seconds
            current_time = time.time()
            interval = 10
            
            print(Fore.RED ,"\n--- Throughput (bps) ---")
            for protocol, bytes_count in self.throughput_data.items():
                throughput_bps = (bytes_count * 8) / interval
                
                # Store timestamp and throughput value
                self.throughput_history[protocol]['times'].append(
                    (current_time - self.start_time) / 60  # Convert to minutes
                )
                self.throughput_history[protocol]['values'].append(throughput_bps)
                
                print(Fore.BLUE , Back.LIGHTBLUE_EX, f"{protocol}: {throughput_bps:.2f} bps", Back.RESET, Fore.RESET)
                self.throughput_data[protocol] = 0

    def display_statistics(self):

        """Display network statistics periodically"""
        while not self.exit_flag.is_set():
            time.sleep(2)  # Update every 30 seconds
            self.print_current_stats()


    def print_current_stats(self):
        """Print current network statistics"""
        print(Fore.RED ,"\n=== Network Statistics ===\r", Fore.RESET)
        print(f"Unique IP addresses: {len(self.unique_ips)}")
        print(f"Unique MAC addresses: {len(self.unique_macs)}")
        
        for protocol in self.protocol_counts.keys():
            avg_size = (sum(self.packet_sizes[protocol]) / 
                       len(self.packet_sizes[protocol]) 
                       if self.packet_sizes[protocol] else 0)
            print(f"\n{protocol} Statistics:")
            print(f"Total packets: {self.protocol_counts[protocol]}")
            print(f"Average packet size: {avg_size:.2f} bytes")

    def generate_visualizations(self):
        """Generate and save visualization plots"""
        # Improved throughput over time visualization
        plt.figure(figsize=(12, 6))
        for protocol in ['Ethernet', 'TCP', 'UDP']:
            if self.throughput_history[protocol]['values']:  # Only plot if we have data
                plt.plot(
                    self.throughput_history[protocol]['times'],
                    self.throughput_history[protocol]['values'],
                    label=f'{protocol} Throughput',
                    marker='o',
                    markersize=2
                )
        
        plt.title('Network Throughput Over Time')
        plt.xlabel('Time (minutes)')
        plt.ylabel('Throughput (bits per second)')
        plt.grid(True, linestyle='--', alpha=0.7)
        plt.legend()
        plt.tight_layout()
        plt.savefig('throughput_over_time.png', dpi=300, bbox_inches='tight')
        plt.close()

        # Latency distribution
        if self.latency_history:
            plt.figure(figsize=(12, 6))
            plt.hist(self.latency_history, bins=50, edgecolor='black')
            plt.title('Latency Distribution')
            plt.xlabel('Latency (ms)')
            plt.ylabel('Frequency')
            plt.grid(True, linestyle='--', alpha=0.7)
            plt.tight_layout()
            plt.savefig('latency_distribution.png', dpi=300, bbox_inches='tight')
            plt.close()

        # Protocol usage
        plt.figure(figsize=(12, 6))
        protocols = list(self.protocol_counts.keys())
        counts = list(self.protocol_counts.values())
        plt.bar(protocols, counts, edgecolor='black')
        plt.title('Protocol Usage')
        plt.xlabel('Protocol')
        plt.ylabel('Number of Packets')
        plt.grid(True, axis='y', linestyle='--', alpha=0.7)
        plt.tight_layout()
        plt.savefig('protocol_usage.png', dpi=300, bbox_inches='tight')
        plt.close()

    def start_monitoring_threads(self):
        """Start monitoring threads"""
        threading.Thread(target=self.calculate_throughput, daemon=True).start()
        threading.Thread(target=self.display_statistics, daemon=True).start()

    def stop_monitoring(self):
        """Stop monitoring and display final statistics"""
        self.exit_flag.set()
        print(Fore.YELLOW, Back.BLACK , "\n=== Final Statistics ===", Back.RESET, Fore.RESET)
        self.print_current_stats()
        self.generate_visualizations()

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\nStopping network monitoring...")
    monitor.stop_monitoring()
    sys.exit(0)

if __name__ == "__main__":
    # Set up signal handler for graceful termination
    signal.signal(signal.SIGINT, signal_handler)
    
    # Create and start network monitor
    monitor = NetworkMonitor()
    
    print("Starting network monitoring... Press Ctrl+C to stop.")
    
    try:
        # Start packet capture
        sniff(prn=monitor.packet_callback, store=False)
    except KeyboardInterrupt:
        monitor.stop_monitoring()
