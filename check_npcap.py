# check_npcap.py
import os
import sys

print("Checking Npcap installation...")
print("="*60)

# Check if Npcap is installed
npcap_paths = [
    r"C:\Program Files\Npcap",
    r"C:\Program Files (x86)\Npcap",
    r"C:\Windows\System32\Npcap",
    r"C:\Windows\SysWOW64\Npcap"
]

found = False
for path in npcap_paths:
    if os.path.exists(path):
        print(f"✅ Found Npcap at: {path}")
        found = True
        # List files
        try:
            files = os.listdir(path)
            print(f"   Files: {', '.join(files[:5])}...")
        except:
            pass

if not found:
    print("❌ Npcap not found in standard locations")
    print("\nPlease install Npcap from: https://npcap.com")
    print("Make sure to check 'WinPcap API-compatible Mode'")
    
print("\n" + "="*60)

# Test Scapy
try:
    from scapy.all import *
    print(f"✅ Scapy version: {scapy.__version__}")
    
    # Test if we can capture
    print("Testing packet capture capability...")
    conf.use_pcap = True
    
    # Try to get interfaces
    ifaces = get_if_list()
    print(f"✅ Found {len(ifaces)} interfaces")
    
    # Try a simple capture test
    print("\nTrying to capture 1 packet (timeout: 3 seconds)...")
    try:
        result = sniff(count=1, timeout=3, store=True)
        if result:
            print("✅ SUCCESS! Can capture packets")
        else:
            print("⚠️  No packets captured (might be no traffic)")
    except Exception as e:
        print(f"❌ Capture failed: {e}")
        
except Exception as e:
    print(f"❌ Scapy error: {e}")

print("="*60)
input("\nPress Enter to exit...")