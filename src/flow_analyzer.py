import os
import ctypes
from adapter import Adapter
OUTPUT_ARGUS_FILE = "flow_out.argus"
OUTPUT_FILE = "flow_out.txt"


# def hash_16_b(word): return ctypes.c_uint64(
#     hash(word)).value.to_bytes(8, "big").hex()


argus_display_filters = [
    "smac", "dmac", "rank", "saddr", "daddr", "sport", "dport", "proto", "sbytes", "dbytes", "spkts", "dpkts", "dur",
    "state", "flgs", "tcpopt", "swin", "dwin", "tcprtt", "synack", "ackdat", "sload", "dload", "sttl", "dttl",
    "smaxsz", "sminsz", "dmaxsz", "dminsz", "sappbytes", "dappbytes", "sretrans", "dretrans", "pretrans", "psretrans",
]

ARGUS_FIELDS = [
    'SrcMac', 'DstMac', 'Rank', 'SrcAddr', 'DstAddr', 'Sport', 'Dport', 'Proto', 'SrcBytes', 'DstBytes', 'SrcPkts', 'DstPkts',
    'Dur', 'State', 'Flgs', 'TcpOpt', 'SrcWin', 'DstWin', 'TcpRtt', 'SynAck', 'AckDat', 'SrcLoad', 'DstLoad', 'sTtl',
    'dTtl', 'sMaxPktSz', 'sMinPktSz', 'dMaxPktSz', 'dMinPktSz', 'SAppBytes', 'DAppBytes', 'SrcRetra', 'DstRetra', 'pRetran'
]
ARGUS_STR_FIELDS = [
    "SrcMac", "DstMac", "SrcAddr", "DstAddr", "Proto", "State", "Flgs", "TcpOpt",
]
DEFAULT_STR = 'unknown'


class Flow:
    def __init__(self, fields):
        self.records = {}
        self.field_idxs = {}
        # store the idx occurance of every field
        for idx in range(len(fields)):
            if fields[idx] in ARGUS_FIELDS:
                self.field_idxs[fields[idx]] = idx

    def get_record_by_key(self, k):
        if k in self.records: 
            return self.records[k]
        return None

    def get_records(self,):
        return self.records
    def get_headers(self,):
        return self.headers

    def add_record(self, row):
        data = {"severity": 0}
        # assign flow data
        for key, value in self.field_idxs.items():
            if not row[self.field_idxs[key]]:
                data[key] = DEFAULT_STR if key in ARGUS_STR_FIELDS else 0
            else:
                data[key] = row[self.field_idxs[key]]
        if not data["SrcAddr"] or not data["DstAddr"]:
            return
        # now construct key
        key = "{}/{}/{}/{}/{}".format(
            data["SrcAddr"], data["DstAddr"], data["Proto"], data["Sport"], data["Dport"])
        self.records[key] = data


class Flow_Analyzer(Adapter):
    def __init__(self, argus_path, argus_client_path, pcap_file, tmp_folder=None):
        super().__init__(tmp_folder)
        self.argus_path = argus_path
        self.argus_client_path = argus_client_path
        self.pcap_file = pcap_file
        self.out_argus = os.path.join(self.tmp, OUTPUT_ARGUS_FILE)
        self.out = os.path.join(self.tmp, OUTPUT_FILE)
        self.flow = None
        self.headers = []
    
    def get_flow_records(self):
        return self.flow.get_records()

    def get_flow_headers(self, for_csv=True):
        if not for_csv:
            return self.headers
        hdrs_copy = self.headers[:]
        for hf in ["SrcMac", "DstMac", "SrcAddr", "DstAddr"]:
            hdrs_copy.remove(hf)
        return hdrs_copy 


    
    def update_flow_record(self, p):
        switch_v = [False, True]
        # for both src/dst and dst/src combinations
        for s_arg in switch_v:
            key = p.get_argus_key(s_arg)
            # get record from argus
            record = self.flow.get_record_by_key(key)
            if record:
                record["severity"] = p.get_priority()
                p.set_argus_rank(record["Rank"])
                return

    def create_flow(self,):
        run_argus = "{} -A -m -J -R -Z -r {} -w {}"\
            .format(self.argus_path, self.pcap_file, self.out_argus)
        self.run_cmd(run_argus)
        # now parse argus output into a file
        display_filters_str = " ".join(
            ["-s {}".format(s) for s in argus_display_filters])
        parse_argus_output = "{} -X -c ',' -n {} -r {} > {}"\
            .format(self.argus_client_path, display_filters_str, self.out_argus, self.out)
        self.run_cmd(parse_argus_output)
        with open(self.out, 'r') as f:
            self.headers = f.readline().strip().split(",")
            self.headers.append("severity")
            self.flow = Flow(self.headers)
            nl = f.readline()
            while nl != '':
                if not nl:
                    nl = f.readline()
                    continue
                self.flow.add_record(nl.strip().split(','))
                nl = f.readline()
