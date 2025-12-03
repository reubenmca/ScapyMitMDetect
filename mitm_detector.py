#!/usr/bin/env python3
"""
SCAPY MitM Attack Detector
Code purpose: Compare the MAC address of default gateway over time
To monitor potential presence of MitM Attack
"""

import time
import sys
from scapy.all import conf, ARP, Ether, srp


def get_gateway_info():
    """Get gateway IP and MAC address."""
    gateway_ip = conf.route.route("0.0.0.0")[2]
    print(f"Gateway IP: {gateway_ip}")
    
    # Generate ARP request to get gateway MAC address
    arp_request = ARP(pdst=gateway_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    gateway_mac = answered_list[0][1].hwsrc if answered_list else None
    print(f"Gateway MAC Address: {gateway_mac}")
    
    return gateway_ip, gateway_mac


def monitor_gateway(gateway_ip, gateway_mac, interval=5):
    """
    Continuously monitor gateway MAC address.
    
    Args:
        gateway_ip: IP address of the gateway
        gateway_mac: Original MAC address of the gateway
        interval: Time in seconds between checks (default: 5)
    """
    arp_request = ARP(pdst=gateway_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    
    print(f"\n[*] Starting monitoring (checking every {interval} seconds)...")
    print("[*] Press Ctrl+C to stop\n")
    
    try:
        while True:
            current_answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            current_mac = current_answered_list[0][1].hwsrc if current_answered_list else None
            
            if current_mac and current_mac != gateway_mac:
                print(f"\033[91m[*] Possible ARP spoof attack! Expected MAC: {gateway_mac}, Received MAC: {current_mac}\033[0m")
            else:
                print(f"\033[92m[+] Gateway is {gateway_ip} at {gateway_mac}\033[0m")
            
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped")
        sys.exit(0)


def main():
    """Main entry point."""
    print("=== SCAPY MitM Attack Detector ===\n")
    
    try:
        gateway_ip, gateway_mac = get_gateway_info()
        
        if not gateway_mac:
            print("[!] Error: Could not retrieve gateway MAC address")
            sys.exit(1)
        
        monitor_gateway(gateway_ip, gateway_mac)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
