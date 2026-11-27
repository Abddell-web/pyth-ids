# Fake traffic so you can test without root or a real network
import random
import time


def tcp_syn(src, dst, port):
    return {"time": time.time(), "proto": "TCP", "src": src, "dst": dst,
            "sport": random.randint(1024, 65535), "dport": port, "flags": "S",
            "mac": None, "arp_op": None, "icmp_type": None}


def run_simulation(detector):
    while True:
        print("--- simulating port scan")
        for port in range(1, 40):
            detector.process(tcp_syn("203.0.113.7", "10.0.0.5", port))

        print("--- simulating SSH brute force")
        for _ in range(20):
            detector.process(tcp_syn("198.51.100.9", "10.0.0.5", 22))

        print("--- simulating SYN flood")
        for _ in range(200):
            fake_ip = f"192.0.2.{random.randint(1, 254)}"
            detector.process(tcp_syn(fake_ip, "10.0.0.1", 80))

        print("--- simulating ICMP flood")
        for _ in range(70):
            detector.process({"time": time.time(), "proto": "ICMP", "src": "198.51.100.77",
                              "dst": "10.0.0.2", "sport": None, "dport": None,
                              "flags": "", "mac": None, "arp_op": None, "icmp_type": 8})

        print("--- simulating ARP spoofing")
        for mac in ("aa:aa:aa:aa:aa:01", "bb:bb:bb:bb:bb:02"):
            detector.process({"time": time.time(), "proto": "ARP", "src": "10.0.0.1",
                              "dst": "10.0.0.9", "sport": None, "dport": None,
                              "flags": "", "mac": mac, "arp_op": 2, "icmp_type": None})

        time.sleep(40)  # wait for the cooldown to expire, then repeat