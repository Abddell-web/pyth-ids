DB_FILE = "alerts.db"
INTERFACE = None          # None = default interface

COOLDOWN = 30             # seconds before the same alert can fire again

PORT_SCAN_PORTS = 20      # different ports hit by one IP...
PORT_SCAN_WINDOW = 10     # ...within this many seconds

SYN_FLOOD_COUNT = 150     # SYN packets to one target...
SYN_FLOOD_WINDOW = 5      # ...within this many seconds

ICMP_FLOOD_COUNT = 60
ICMP_FLOOD_WINDOW = 5

BRUTE_FORCE_COUNT = 15
BRUTE_FORCE_WINDOW = 60
BRUTE_FORCE_PORTS = {22: "SSH", 21: "FTP", 23: "Telnet", 3389: "RDP", 3306: "MySQL",5900: "VNC"}
