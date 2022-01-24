import subprocess
from sys import stderr
import json
from verdict import Verdict

# A snort adapter
MAX_PKT_SIZE = 65535
OUTPUT_FILE = 'alert_json.txt'

class Snort:
    def __init__(self, snort_path, config_path, pcap_path,
        max_pkt_size = MAX_PKT_SIZE, k='none'):
        self.snort_path = snort_path
        self.config_path = config_path
        self.pcap_path = pcap_path
        self.max_pkt_size = max_pkt_size
        self.k = k
        self.verdict_store = {}

    def analyze_packets(self,):
        cmd = "{} -c {} -s {}\\\n -k {} -l . -r {}"\
            .format(self.snort_path, self.config_path,\
                self.max_pkt_size, self.k, self.pcap_path)
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
        if result.returncode != 0:
            print (result.stderr)
            raise Exception(result.stderr)
        # now read the created file
        with open(OUTPUT_FILE, 'r') as f:
            for l in f:
                log_json = json.loads(l)
                # create new verdict from log
                new_verdict = Verdict(log_json)
                self.verdict_store[new_verdict.get_packet_id()] = new_verdict
        # delete the log file
        subprocess.run('rm {}'.format(OUTPUT_FILE), shell=True, stdout=subprocess.PIPE)
    
    def get_verdict_for_packet(self, pac_id):
        if pac_id in self.verdict_store:
            return self.verdict_store[pac_id]
        return Verdict({ "pkt_num": pac_id })
