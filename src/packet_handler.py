import csv
import sys
import subprocess
import pyshark
import os
from alive_progress import alive_bar
sys.path.insert(1, './src/proto')
from packet import Packet


counter = 0
ipcounter = 0
tcpcounter = 0
udpcounter = 0

OUTPUT_DIR = 'csv'


class Packet_Store:
    def __init__(self, ):
        self.pcount = 0
        self.mcount = 0
        self.packets = []

    def add_packet(self, p):
        self.pcount += 1
        if p.attention():
            self.mcount += 1
        self.packets.append(p)

    def get_packets(self):
        return self.packets

    def get_packet_count(self,):
        return self.pcount

    def get_mallicious_count(self,):
        return self.mcount


class PacketHandler:
    def __init__(self, pcap_file, verbose, snort_adptr=None):
        self.pcap_file = pcap_file
        self.verbose = verbose
        self.packets = {}
        self.snort_adptr = snort_adptr
        self.nof_packets = 0

    def parse_pcap(self,):
        # read the packets and store the basic fields
        with alive_bar(self.nof_packets) as bar:
            cap_packets = pyshark.FileCapture(
                self.pcap_file, keep_packets=False)
            while True:
                try:
                    pp = cap_packets.next()
                    p = Packet(pp)
                    if self.snort_adptr:
                        # now attach the verdict to the packet
                        p.assign_snort_verdict(
                            self.snort_adptr.get_verdict_for_packet(
                                p.get_idx())
                        )
                    p_layers = p.get_layers_str()
                    if p_layers not in self.packets:
                        self.packets[p_layers] = Packet_Store()
                    self.packets[p_layers].add_packet(p)
                    if self.verbose:
                        print(p)
                except StopIteration:
                    break
                bar()

    def get_pcap_meta(self,):
        ps = subprocess.Popen(
            ('tshark', '-r', self.pcap_file), stdout=subprocess.PIPE)
        self.nof_packets = int(subprocess.check_output(
            ('wc', '-l'), stdin=ps.stdout).strip())

    def analyze_packets(self,):
        # first analyze the pcap with snort
        if self.snort_adptr:
            self.snort_adptr.analyze_packets()

    def captured_packet_stats(self,):
        s = ""
        return "\n".join(["{}[Mal packets/Total packets]: {}/{}\n"
            .format(ps, self.packets[ps].get_mallicious_count(), self.packets[ps].get_packet_count())
            for ps in self.packets.keys()])

    def _prepare_csv_folder(self,):
        if not os.path.exists(OUTPUT_DIR):
            os.makedirs(OUTPUT_DIR)
        # remove last 4 chars from path to get file name
        fname = os.path.basename(self.pcap_file)[:-5]
        csv_folder = os.path.join(OUTPUT_DIR, fname)
        if not os.path.exists(csv_folder):
            os.makedirs(csv_folder)
        return csv_folder

    def generate_csv(self,):
        csv_folder = self._prepare_csv_folder()
        with alive_bar(len(self.packets.keys())) as bar:
            for psk in self.packets.keys():
                packet_store = self.packets[psk]
                fieldnames = None
                with open('{}/{}_traffic.csv'.format(csv_folder, psk), mode='w') as csv_file:
                    for packet in packet_store.get_packets():
                        packet_data = packet.get_csv_fields()
                        if not fieldnames:
                            fieldnames = packet_data.keys()
                            writer = csv.DictWriter(
                                csv_file, fieldnames=fieldnames)
                            writer.writeheader()
                        writer.writerow(packet_data)
                bar()
        with open('{}/stats.txt'.format(csv_folder), mode='w') as stats_file:
            stats_file.write(self.captured_packet_stats())
