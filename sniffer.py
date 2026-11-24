from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether

import config


def make_packet_dict(raw):
    #Turn a scapy packet into a simple dict
    pkt = {
        "time": float(raw.time),
        "proto": "OTHER",
        "src": None, "dst": None,
        "sport": None, "dport": None,
        "flags": "", "mac": None,
        "arp_op": None, "icmp_type": None,
    }

    if raw.haslayer(ARP):
        pkt["proto"] = "ARP"
        pkt["src"] = raw[ARP].psrc
        pkt["dst"] = raw[ARP].pdst
        pkt["mac"] = raw[ARP].hwsrc
        pkt["arp_op"] = int(raw[ARP].op)
        return pkt

    if not raw.haslayer(IP):
        return None

    pkt["src"] = raw[IP].src
    pkt["dst"] = raw[IP].dst
    if raw.haslayer(Ether):
        pkt["mac"] = raw[Ether].src

    if raw.haslayer(TCP):
        pkt["proto"] = "TCP"
        pkt["sport"] = int(raw[TCP].sport)
        pkt["dport"] = int(raw[TCP].dport)
        pkt["flags"] = str(raw[TCP].flags)
    elif raw.haslayer(UDP):
        pkt["proto"] = "UDP"
        pkt["sport"] = int(raw[UDP].sport)
        pkt["dport"] = int(raw[UDP].dport)
    elif raw.haslayer(ICMP):
        pkt["proto"] = "ICMP"
        pkt["icmp_type"] = int(raw[ICMP].type)

    return pkt


def start_sniffing(detector):
    def handle(raw):
        pkt = make_packet_dict(raw)
        if pkt:
            detector.process(pkt)

    print("Sniffing... (needs root/admin)")
    try:
        sniff(prn=handle, store=False, iface=config.INTERFACE)
    except PermissionError:
        print("ERROR: run as root/administrator to capture packets")