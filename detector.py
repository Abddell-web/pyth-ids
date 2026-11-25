from collections import defaultdict

import config
import database
import time


def remove_old(entries, now, window):
    """Keep only entries (time, ...) that are inside the time window."""
    return [e for e in entries if now - e[0] <= window]


class Detector:
    def __init__(self):
        # each dict holds recent activity so we can count things over time
        self.port_hits = defaultdict(list)    # src_ip -> [(time, dst_ip, port)]
        self.syn_hits = defaultdict(list)     # dst_ip -> [(time, src_ip)]
        self.icmp_hits = defaultdict(list)    # src_ip -> [(time, dst_ip)]
        self.login_hits = defaultdict(list)   # (src, dst, port) -> [(time,)]
        self.arp_table = {}                   # ip -> mac we saw first
        self.last_alert = {}                  # to avoid spamming the same alert

    def raise_alert(self, rule, severity, src, dst, message):
        key = (rule, src, dst)
        now = time.time()
        if now - self.last_alert.get(key, 0) < config.COOLDOWN:
            return
        self.last_alert[key] = now

        database.save_alert(rule, severity, src, dst, message)
        print(f"[{severity.upper()}] {rule}: {message}")

    def process(self, pkt):
        """pkt is a dict made by sniffer.py"""
        now = pkt["time"]

        is_syn = pkt["proto"] == "TCP" and "S" in pkt["flags"] and "A" not in pkt["flags"]

        if is_syn:
            self.check_port_scan(pkt, now)
            self.check_syn_flood(pkt, now)
            self.check_brute_force(pkt, now)

        if pkt["proto"] == "ICMP" and pkt["icmp_type"] == 8:
            self.check_icmp_flood(pkt, now)

        if pkt["proto"] == "ARP" and pkt["arp_op"] == 2:
            self.check_arp_spoof(pkt)

    def check_port_scan(self, pkt, now):
        src = pkt["src"]
        self.port_hits[src].append((now, pkt["dst"], pkt["dport"]))
        self.port_hits[src] = remove_old(self.port_hits[src], now, config.PORT_SCAN_WINDOW)

        targets = set((dst, port) for _, dst, port in self.port_hits[src])
        if len(targets) >= config.PORT_SCAN_PORTS:
            self.raise_alert(
                "port_scan", "medium", src, pkt["dst"],
                f"{src} probed {len(targets)} ports in {config.PORT_SCAN_WINDOW}s",
            )
            self.port_hits[src] = []

    def check_syn_flood(self, pkt, now):
        dst = pkt["dst"]
        self.syn_hits[dst].append((now, pkt["src"]))
        self.syn_hits[dst] = remove_old(self.syn_hits[dst], now, config.SYN_FLOOD_WINDOW)

        if len(self.syn_hits[dst]) >= config.SYN_FLOOD_COUNT:
            sources = set(src for _, src in self.syn_hits[dst])
            self.raise_alert(
                "syn_flood", "critical", pkt["src"], dst,
                f"{dst} received {len(self.syn_hits[dst])} SYN packets from {len(sources)} sources",
            )
            self.syn_hits[dst] = []

    def check_icmp_flood(self, pkt, now):
        src = pkt["src"]
        self.icmp_hits[src].append((now, pkt["dst"]))
        self.icmp_hits[src] = remove_old(self.icmp_hits[src], now, config.ICMP_FLOOD_WINDOW)

        if len(self.icmp_hits[src]) >= config.ICMP_FLOOD_COUNT:
            self.raise_alert(
                "icmp_flood", "high", src, pkt["dst"],
                f"{src} sent {len(self.icmp_hits[src])} pings in {config.ICMP_FLOOD_WINDOW}s",
            )
            self.icmp_hits[src] = []

    def check_brute_force(self, pkt, now):
        service = config.BRUTE_FORCE_PORTS.get(pkt["dport"])
        if service is None:
            return

        key = (pkt["src"], pkt["dst"], pkt["dport"])
        self.login_hits[key].append((now,))
        self.login_hits[key] = remove_old(self.login_hits[key], now, config.BRUTE_FORCE_WINDOW)

        if len(self.login_hits[key]) >= config.BRUTE_FORCE_COUNT:
            self.raise_alert(
                "brute_force", "high", pkt["src"], pkt["dst"],
                f"Possible {service} brute force: {len(self.login_hits[key])} attempts from {pkt['src']}",
            )
            self.login_hits[key] = []

    def check_arp_spoof(self, pkt):
        ip = pkt["src"]
        mac = pkt["mac"]

        if ip not in self.arp_table:
            self.arp_table[ip] = mac
        elif self.arp_table[ip] != mac:
            old_mac = self.arp_table[ip]
            self.arp_table[ip] = mac
            self.raise_alert(
                "arp_spoof", "high", ip, pkt["dst"],
                f"{ip} changed MAC from {old_mac} to {mac} (possible ARP spoofing)",
            )