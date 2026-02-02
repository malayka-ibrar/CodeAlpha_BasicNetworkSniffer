#!/usr/bin/env python3
"""
Basic Network Sniffer - CodeAlpha Task 1
CORRECTED VERSION - No timeout issue
"""

import sys
import time
import platform
from datetime import datetime

# Check if running as Administrator on Windows
if platform.system() == "Windows":
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            print("\n" + "="*60)
            print("⚠️  ADMINISTRATOR PRIVILEGES REQUIRED!")
            print("="*60)
            print("Please run as Administrator:")
            print("1. Right-click Command Prompt")
            print("2. Select 'Run as administrator'")
            print("3. Navigate to script folder")
            print("4. Run: python network_sniffer.py")
            print("="*60)
            sys.exit(1)
    except:
        pass

# Import Scapy
try:
    from scapy.all import sniff, conf, get_if_list, get_if_addr
    from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether, Raw
    from scapy.all import send
    import scapy.all as scapy
except ImportError:
    print("\n" + "="*60)
    print("❌ SCAPY NOT INSTALLED!")
    print("="*60)
    print("Install with: pip install scapy")
    print("Or: pip install --pre scapy[complete]")
    print("="*60)
    sys.exit(1)

class NetworkSniffer:
    def __init__(self, interface=None, count=20, filter_rule="ip or arp"):
        self.interface = interface
        self.packet_count = count
        self.filter_rule = filter_rule
        self.captured_packets = []
        self.start_time = None
        self.stopped = False  # Add this flag
        
    def list_interfaces_simple(self):
        """Simple interface listing"""
        print("\n" + "="*60)
        print("📡 NETWORK INTERFACES")
        print("="*60)
        
        try:
            interfaces = get_if_list()
            
            if not interfaces:
                print("No interfaces found!")
                return {}
            
            print(f"\nFound {len(interfaces)} interface(s):")
            print("-" * 40)
            
            interface_map = {}
            for i, ifname in enumerate(interfaces, 1):
                print(f"{i}. {ifname}")
                
                # Try to get IP address
                try:
                    ip_addr = get_if_addr(ifname)
                    if ip_addr and ip_addr != "0.0.0.0":
                        print(f"   IP: {ip_addr}")
                except:
                    pass
                
                interface_map[ifname] = ifname
            
            print("-" * 40)
            
            # Suggest interfaces for Windows
            if platform.system() == "Windows":
                print("\n💡 For Windows, try:")
                print("   • 'Wi-Fi'")
                print("   • 'Ethernet'")
                print("   • Or use device name shown above")
            
            return interface_map
            
        except Exception as e:
            print(f"Error: {e}")
            return {}
    
    def packet_handler(self, packet):
        """Process each captured packet"""
        try:
            packet_num = len(self.captured_packets) + 1
            self.captured_packets.append(packet)
            
            print(f"\n[📦] Packet #{packet_num}")
            print(f"    Time: {datetime.now().strftime('%H:%M:%S')}")
            
            # Basic info
            print(f"    Summary: {packet.summary()}")
            
            # Check for IP layer
            if packet.haslayer(IP):
                ip = packet[IP]
                print(f"    From: {ip.src} → To: {ip.dst}")
                
                if packet.haslayer(TCP):
                    tcp = packet[TCP]
                    print(f"    TCP Ports: {tcp.sport} → {tcp.dport}")
                    
                    # Common services
                    services = {80: "HTTP", 443: "HTTPS", 22: "SSH", 
                               25: "SMTP", 53: "DNS"}
                    
                    src = services.get(tcp.sport, "")
                    dst = services.get(tcp.dport, "")
                    
                    if src or dst:
                        print(f"    Service: {src} → {dst}")
                
                elif packet.haslayer(UDP):
                    udp = packet[UDP]
                    print(f"    UDP Ports: {udp.sport} → {udp.dport}")
                
                elif packet.haslayer(ICMP):
                    print(f"    Protocol: ICMP")
                
                print(f"    Size: {len(packet)} bytes")
            
            elif packet.haslayer(ARP):
                arp = packet[ARP]
                print(f"    ARP: {arp.psrc} → {arp.pdst}")
            
            print("-" * 50)
            
            # Stop if reached count
            if 0 < self.packet_count <= packet_num:
                self.stopped = True
                return True
            
            return False
            
        except Exception as e:
            print(f"    Error: {str(e)[:50]}")
            return False
    
    def start_sniffing(self):
        """Start packet capture"""
        print("\n" + "="*60)
        print("🚀 NETWORK SNIFFER - CodeAlpha Task 1")
        print("="*60)
        print(f"Interface: {self.interface if self.interface else 'Auto'}")
        print(f"Packets: {self.packet_count}")
        print(f"Filter: {self.filter_rule}")
        print("="*60)
        
        print("\n[▶] Starting capture... Press Ctrl+C to stop")
        print("[💡] Run 'test_traffic.py' in another window")
        print("[💡] OR open browser or run ping commands")
        print()
        
        self.start_time = time.time()
        
        try:
            # REMOVED timeout parameter - this was the problem!
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                count=self.packet_count,  # Will stop after this many packets
                filter=self.filter_rule,
                store=False
                # timeout=30  # REMOVED THIS LINE
            )
            
        except KeyboardInterrupt:
            print("\n\n[⏹] Stopped by user")
        except Exception as e:
            print(f"\n[❌] Error: {e}")
        finally:
            self.show_summary()
    
    def show_summary(self):
        """Show capture summary"""
        if not self.captured_packets:
            print("\n" + "="*60)
            print("❌ NO PACKETS CAPTURED!")
            print("="*60)
            print("\nQuick fix:")
            print("1. Open ANOTHER Command Prompt")
            print("2. Run: python test_traffic.py")
            print("3. OR open a website in browser")
            print("="*60)
            return
        
        duration = time.time() - self.start_time
        
        print("\n" + "="*60)
        print("📊 CAPTURE SUMMARY")
        print("="*60)
        print(f"Total packets: {len(self.captured_packets)}")
        print(f"Duration: {duration:.2f} seconds")
        
        # Count protocols
        protocols = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0, 'Other': 0}
        
        for packet in self.captured_packets:
            if packet.haslayer(TCP):
                protocols['TCP'] += 1
            elif packet.haslayer(UDP):
                protocols['UDP'] += 1
            elif packet.haslayer(ICMP):
                protocols['ICMP'] += 1
            elif packet.haslayer(ARP):
                protocols['ARP'] += 1
            else:
                protocols['Other'] += 1
        
        print(f"\nProtocol breakdown:")
        for proto, count in protocols.items():
            if count > 0:
                percent = (count / len(self.captured_packets)) * 100
                print(f"  {proto}: {count} ({percent:.1f}%)")
        
        print("="*60)
        print("\n✅ Task 1: Basic Network Sniffer - COMPLETED")
        print("="*60)

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Network Packet Sniffer")
    parser.add_argument("-i", "--interface", help="Network interface", default=None)
    parser.add_argument("-l", "--list", help="List interfaces", action="store_true")
    parser.add_argument("-c", "--count", type=int, help="Packets to capture", default=15)
    parser.add_argument("-f", "--filter", help="BPF filter", default="ip or arp")
    
    args = parser.parse_args()
    
    # Create sniffer
    sniffer = NetworkSniffer(
        interface=args.interface,
        count=args.count,
        filter_rule=args.filter
    )
    
    # List interfaces
    if args.list:
        sniffer.list_interfaces_simple()
        return
    
    # Start sniffing
    sniffer.start_sniffing()

if __name__ == "__main__":
    print("\n" + "="*60)
    print("🔍 BASIC NETWORK SNIFFER - CodeAlpha Cybersecurity")
    print("="*60)
    
    # Run main
    main()