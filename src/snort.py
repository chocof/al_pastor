import subprocess
import os
from sys import stderr
import json
from adapter import Adapter
from verdict import Verdict

# A snort adapter
MAX_PKT_SIZE = 65535
OUTPUT_FILE = 'alert_json.txt'

class Snort(Adapter):
    def __init__(self, snort_path, config_path, pcap_path,
        max_pkt_size = MAX_PKT_SIZE, k='none', tmp_folder=None):
        super().__init__(tmp_folder)
        self.snort_path = snort_path
        self.config_path = config_path
        self.pcap_path = pcap_path
        self.max_pkt_size = max_pkt_size
        self.k = k
        self.verdict_store = {}
        self.out = os.path.join(self.tmp, OUTPUT_FILE)

    def analyze_packets(self,):
        cmd = "{} -c {} -s {}\\\n -k {} -l {} -r {}"\
            .format(self.snort_path, self.config_path,\
                self.max_pkt_size, self.k, self.tmp, self.pcap_path)
        self.run_cmd(cmd)
        # now read the created file
        with open(self.out, 'r') as f:
            for l in f:
                log_json = json.loads(l)
                # create new verdict from log
                new_verdict = Verdict(log_json)
                self.verdict_store[new_verdict.get_packet_id()] = new_verdict
    
    def get_verdict_for_packet(self, pac_id):
        if pac_id in self.verdict_store:
            return self.verdict_store[pac_id]
        return Verdict({ "pkt_num": pac_id })
