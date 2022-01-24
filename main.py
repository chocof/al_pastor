import sys

from dpkt import pcap
sys.path.insert(1, './src')
from packet_handler import PacketHandler
from snort import Snort

RUN_SNORT = True
VERBOSE = False
GENERATE_CSV = True

snort_path = "snort"
snort_config_path = "~/projects/snort_instance/etc/snort.lua"
pcap_file = "./pcaps/normal_1.pcap"

snort = None
if RUN_SNORT:
    snort = Snort(snort_path, snort_config_path, pcap_file)
phandler = PacketHandler(pcap_file, VERBOSE, snort)

print("[+] Getting pcap's meta info...")
phandler.get_pcap_meta()

if RUN_SNORT:
    print("[+] Using Snort to analyze packets...")
    phandler.analyze_packets()
print("[+] Parsing PCAP file:")
phandler.parse_pcap()
print("[+] Packets parsed:")
print(phandler.captured_packet_stats())
if GENERATE_CSV:
    print("[+] Generating CSV files:")
    phandler.generate_csv()
