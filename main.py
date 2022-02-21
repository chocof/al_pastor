import sys
import argparse
from dpkt import pcap
sys.path.insert(1, './src')
from packet_handler import PacketHandler
from snort import Snort
from flow_analyzer import Flow_Analyzer

RUN_SNORT = True
RUN_FLOW_ANALYZER = False
VERBOSE = False
GENERATE_CSV = True

DEAFULT_ARGUS_PATH = "argus"
DEFAULT_ARGUS_CLIENT_PATH = "ra"
DEFAULT_SNORT_PATH = "snort"
DEFAULT_SNORT_CONFIG_PATH = "/etc/snort.lua"
OUTPUT_DIR = 'csv'

def parse_args():
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('-p', metavar='pcap', type=str, help='location of pcap file to parse', required=True)
    parser.add_argument('-s', metavar='snort', type=str, help='location of snort bin', default=DEFAULT_SNORT_PATH)
    parser.add_argument('--sc', metavar='snort-config', type=str, help='location of snort configuration', 
        default=DEFAULT_SNORT_CONFIG_PATH)
    parser.add_argument('-a', metavar='argus', type=str, help='location of argus bin', default=DEAFULT_ARGUS_PATH)
    parser.add_argument('--ac', metavar='argus-client', type=str, help='location of argus client bin', 
        default=DEFAULT_ARGUS_CLIENT_PATH)
    parser.add_argument('--ds', help='do not run snort', action='store_true')
    parser.add_argument('--da', help='do not run argus', action='store_true')
    parser.add_argument('--csv', help='generate csv files', action='store_true')
    parser.add_argument('-o', help='output directory', default=OUTPUT_DIR)
    
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    
    snort = None
    fa = None
    if not args.ds:
        snort = Snort(args.s, args.sc, args.p)
    if not args.da:
        fa = Flow_Analyzer(args.a, args.ac, args.p)
    phandler = PacketHandler(args.p, snort, fa, VERBOSE)

    print("[+] Getting pcap's meta info...")
    phandler.get_pcap_meta()

    if not args.da:
        print("[+] Constructing Netflow...")
        phandler.construct_netflow()
    if not args.ds:
        print("[+] Using Snort to analyze packets...")
        phandler.analyze_packets()
    print("[+] Parsing PCAP file:")
    phandler.parse_pcap()
    print("[+] Packets parsed:")
    print(phandler.captured_packet_stats())
    if args.csv:
        print("[+] Generating CSV files:")
        phandler.generate_csv(args.o)

    print("[+] Cleaning up")
    if not args.da:
        fa.cleanup()
    if not args.ds:
        snort.cleanup()