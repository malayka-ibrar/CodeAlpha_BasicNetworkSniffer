# test_traffic.py - Create this file
from scapy.all import *
import time
import sys

print("="*60)
print("🚀 TEST TRAFFIC GENERATOR")
print("="*60)

def send_test_packets():
    """Send test packets to generate network traffic"""
    print("Sending test packets...")
    print("Keep this running while your sniffer is capturing")
    print("-" * 50)
    
    # Common destinations
    destinations = [
        "8.8.8.8",      # Google DNS
        "1.1.1.1",      # Cloudflare DNS  
        "google.com",
        "facebook.com",
        "youtube.com"
    ]
    
    packet_count = 0
    
    try:
        while True:
            for dest in destinations:
                try:
                    # Send ICMP (ping) packet
                    send(IP(dst=dest)/ICMP(), verbose=0)
                    packet_count += 1
                    print(f"[{packet_count}] Sent ICMP ping to {dest}")
                    
                    # Send TCP SYN packet (like opening a connection)
                    send(IP(dst=dest)/TCP(dport=80, flags="S"), verbose=0)
                    packet_count += 1
                    print(f"[{packet_count}] Sent TCP SYN to {dest}:80")
                    
                    # Send UDP packet
                    send(IP(dst=dest)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com")), verbose=0)
                    packet_count += 1
                    print(f"[{packet_count}] Sent DNS query to {dest}:53")
                    
                    time.sleep(1)  # Wait 1 second
                    
                except Exception as e:
                    print(f"Error sending to {dest}: {e}")
            
            print(f"\n✅ Sent {packet_count} total packets so far")
            print("Press Ctrl+C to stop\n")
            
    except KeyboardInterrupt:
        print(f"\n\n🎯 FINISHED! Sent {packet_count} test packets")
        print("="*60)

def quick_test():
    """Quick test - send a few packets and exit"""
    print("Quick test - sending 10 packets then stopping")
    
    for i in range(10):
        # Send to different destinations
        dest = "8.8.8.8" if i % 2 == 0 else "1.1.1.1"
        
        # Alternate between ICMP and TCP
        if i % 2 == 0:
            send(IP(dst=dest)/ICMP(), verbose=0)
            print(f"[{i+1}] Sent ICMP to {dest}")
        else:
            send(IP(dst=dest)/TCP(dport=443, flags="S"), verbose=0)
            print(f"[{i+1}] Sent TCP to {dest}:443")
        
        time.sleep(0.5)
    
    print("\n✅ Quick test complete! Sent 10 packets")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate test network traffic")
    parser.add_argument("-q", "--quick", help="Quick test (10 packets)", action="store_true")
    parser.add_argument("-c", "--count", type=int, help="Number of packets to send", default=0)
    
    args = parser.parse_args()
    
    if args.quick:
        quick_test()
    elif args.count > 0:
        print(f"Sending {args.count} packets...")
        for i in range(args.count):
            dest = "8.8.8.8" if i % 2 == 0 else "1.1.1.1"
            send(IP(dst=dest)/ICMP(), verbose=0)
            print(f"[{i+1}] Sent packet to {dest}")
            time.sleep(0.5)
        print(f"\n✅ Sent {args.count} packets")
    else:
        send_test_packets()