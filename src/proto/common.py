class LAYERS:
    ETH="eth"
    ARP="arp"
    DCHP="dchp"
    DNS="dns"
    IP="ip"
    IPV6="ipv6"
    ICMP="icmp"
    UDP="udp"
    TCP="tcp"
    HTTP="http"
    TLS="tls"


UNKNOWN = 'UNKNOWN'
# a list of tcp options
TCP_OPTIONS = {
    # end of option list
    0: 'TCP_OPT_EOL',
    # no operation
    1: 'TCP_OPT_NOP',
    # maximum segment size
    2: 'TCP_OPT_MSS',
    # window scale factor, RFC 1072
    3: 'TCP_OPT_WSCALE',
    # SACK permitted, RFC 2018
    4: 'TCP_OPT_SACKOK',
    # SACK, RFC 2018
    5: 'TCP_OPT_SACK',
    # echo (obsolete), RFC 1072
    6: 'TCP_OPT_ECHO',
    # echo reply (obsolete), RFC 1072
    7: 'TCP_OPT_ECHOREPLY',
    # timestamp, RFC 1323
    8: 'TCP_OPT_TIMESTAMP',
    # partial order conn, RFC 1693
    9: 'TCP_OPT_POCONN',
    # partial order service, RFC 1693
    10: 'TCP_OPT_POSVC',
    # connection count, RFC 1644
    11: 'TCP_OPT_CC',
    # CC.NEW, RFC 1644
    12: 'TCP_OPT_CCNEW',
    # CC.ECHO, RFC 1644
    13: 'TCP_OPT_CCECHO',
    # alt checksum request, RFC 1146
    14: 'TCP_OPT_ALTSUM',
    # alt checksum data, RFC 1146
    15: 'TCP_OPT_ALTSUMDATA',
    # Skeeter
    16: 'TCP_OPT_SKEETER',
    # Bubba
    17: 'TCP_OPT_BUBBA',
    # trailer checksum
    18: 'TCP_OPT_TRAILSUM',
    # MD5 signature, RFC 2385
    19: 'TCP_OPT_MD5',
    # SCPS capabilities
    20: 'TCP_OPT_SCPS',
    # selective negative acks
    21: 'TCP_OPT_SNACK',
    # record boundaries
    22: 'TCP_OPT_REC',
    # corruption experienced
    23: 'TCP_OPT_CORRUPT',
    # SNAP
    24: 'SNAP',
    # TCP Compression Filter
    26: 'TCP_OPT_TCPCOMP',
    # Quick-Start Response
    27: 'QSR',
    # User Timeout Option
    28: 'USO',
    # TCP Authentication Option
    29: 'TCP-AO',
    # Multipath TCP (MPTCP)
    30: 'MPTCP',
    # TCP Fast open cookie
    34: 'TCP_Fast_Open_Cookie',
    # Encryption negotiation
    69: 'TCP-ENO',
    # RFC3692-style Experiment 1
    253: 'MISC_EXP_1',
    # RFC3692-style Experiment 2
    254: 'MISC_EXP_1',
}

ETH_TYPES = {
    0x0800: "Internet Protocol version 4 (IPv4)",
    0x0806: "Address Resolution Protocol (ARP)",
    0x0842: "Wake-on-LAN[9]",
    0x22F0: "Audio Video Transport Protocol (AVTP)",
    0x22F3: "IETF TRILL Protocol",
    0x22EA: "Stream Reservation Protocol",
    0x6002: "DEC MOP RC",
    0x6003: "DECnet Phase IV, DNA Routing",
    0x6004: "DEC LAT",
    0x8035: "Reverse Address Resolution Protocol (RARP)",
    0x809B: "AppleTalk (Ethertalk)",
    0x80F3: "AppleTalk Address Resolution Protocol (AARP)",
    0x8100: "VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq with NNI compatibility[10]",
    0x8102: "Simple Loop Prevention Protocol (SLPP)",
    0x8103: "Virtual Link Aggregation Control Protocol (VLACP)",
    0x8137: "IPX",
    0x8204: "QNX Qnet",
    0x86DD: "Internet Protocol Version 6 (IPv6)",
    0x8808: "Ethernet flow control",
    0x8809: "Ethernet Slow Protocols[11] such as the Link Aggregation Control Protocol (LACP)",
    0x8819: "CobraNet",
    0x8847: "MPLS unicast",
    0x8848: "MPLS multicast",
    0x8863: "PPPoE Discovery Stage",
    0x8864: "PPPoE Session Stage",
    0x887B: "HomePlug 1.0 MME",
    0x888E: "EAP over LAN (IEEE 802.1X)",
    0x8892: "PROFINET Protocol",
    0x889A: "HyperSCSI (SCSI over Ethernet)",
    0x88A2: "ATA over Ethernet",
    0x88A4: "EtherCAT Protocol",
    0x88A8: "Service VLAN tag identifier (S-Tag) on Q-in-Q tunnel.",
    0x88AB: "Ethernet Powerlink[citation needed]",
    0x88B8: "GOOSE (Generic Object Oriented Substation event)",
    0x88B9: "GSE (Generic Substation Events) Management Services",
    0x88BA: "SV (Sampled Value Transmission)",
    0x88BF: "MikroTik RoMON (unofficial)",
    0x88CC: "Link Layer Discovery Protocol (LLDP)",
    0x88CD: "SERCOS III",
    0x88E1: "HomePlug Green PHY",
    0x88E3: "Media Redundancy Protocol (IEC62439-2)",
    0x88E5: "IEEE 802.1AE MAC security (MACsec)",
    0x88E7: "Provider Backbone Bridges (PBB) (IEEE 802.1ah)",
    0x88F7: "Precision Time Protocol (PTP) over IEEE 802.3 Ethernet",
    0x88F8: "NC-SI",
    0x88FB: "Parallel Redundancy Protocol (PRP)",
    0x8902: "IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)",
    0x8906: "Fibre Channel over Ethernet (FCoE)",
    0x8914: "FCoE Initialization Protocol",
    0x8915: "RDMA over Converged Ethernet (RoCE)",
    0x891D: "TTEthernet Protocol Control Frame (TTE)",
    0x893a: "1905.1 IEEE Protocol",
    0x892F: "High-availability Seamless Redundancy (HSR)",
    0x9000: "Ethernet Configuration Testing Protocol[12]",
    0xF1C1: "Redundancy Tag (IEEE 802.1CB Frame Replication and Elimination for Reliability)",
}


def get_eth_type_str(code):
    if code not in ETH_TYPES:
        return UNKNOWN
    return ETH_TYPES[code]


def tcp_opts_to_str(codes):
    '''
    String representation of the codes given as an int array
    '''
    return ','.join([tcp_opt_to_str(code) for code in codes])


def tcp_opt_to_str(code):
    '''
    Returns the label for the given tcp option code
    '''
    return TCP_OPTIONS[code]


def dns_rcode_to_str(code):
    if code > 23:
        return 'NASSIGN'
    return {
        0:	'NOERROR',
        1:	'FORMERR',
        2:	'SERVFAIL',
        3:	'NXDOMAIN',
        4:	'NOTIMP',
        5:	'REFUSED',
        6:	'YXDOMAIN',
        7:	'YXRRSET',
        8:	'NXRRSET',
        9:	'NOTAUTH',
        9:	'NOTAUTH',
        10:	'NOTZONE',
        11:	'DSOTYPENI',
        12: 'NASSIGN',
        13: 'NASSIGN',
        14: 'NASSIGN',
        15: 'NASSIGN',
        16:	'BADVERS',
        16:	'BADSIG',
        17:	'BADKEY',
        18:	'BADTIME',
        19:	'BADMODE',
        20:	'BADNAME',
        21:	'BADALG',
        22:	'BADTRUNC',
        23:	'BADCOOKIE',
    }[code]


# Resource record types for dns
RR_TYPES = {
    1: "A",
    2: "NS",
    3: "MD",
    4: "MF",
    5: "CNAME",
    6: "SOA",
    7: "MB",
    8: "MG",
    9: "MR",
    10: "NULL",
    11: "WKS",
    12: "PTR",
    13: "HINFO",
    14: "MINFO",
    15: "MX",
    16: "TXT",
    17: "RP",
    18: "AFSDB",
    19: "X25",
    20: "ISDN",
    21: "RT",
    22: "NSAP",
    23: "NSAP-PTR",
        24: "SIG",
        25: "KEY",
        26: "PX",
        27: "GPOS",
        28: "AAAA",
        29: "LOC",
        30: "NXT",
        31: "EID",
        32: "NIMLOC",
        33: "SRV",
        34: "ATMA",
        35: "NAPTR",
        36: "KX",
        37: "CERT",
        38: "A6",
        39: "DNAME",
        40: "SINK",
        41: "OPT",
        42: "APL",
        43: "DS",
        44: "SSHFP",
        45: "IPSECKEY",
        46: "RRSIG",
        47: "NSEC",
        48: "DNSKEY",
        49: "DHCID",
        50: "NSEC3",
        51: "NSEC3PARAM",
        52: "TLSA",
        53: "SMIMEA",
        54: "Unassigned",
        55: "HIP",
        56: "NINFO",
        57: "RKEY",
        58: "TALINK",
        59: "CDS",
        60: "CDNSKEY",
        61: "OPENPGPKEY",
        62: "CSYNC",
        63: "ZONEMD",
        64: "SVCB",
        65: "HTTPS",
        66: "Unassigned",
        99: "SPF",
        100: "UINFO",
        101: "UID",
        102: "GID",
        103: "UNSPEC",
        104: "NID",
        105: "L32",
        106: "L64",
        107: "LP",
        108: "EUI48",
        109: "EUI64",
        110: "Unassigned",
        249: "TKEY",
        250: "TSIG",
        251: "IXFR",
        252: "AXFR",
        253: "MAILB",
        254: "MAILA",
        255: "*",
        256: "URI",
        257: "CAA",
        258: "AVC",
        259: "DOA",
        260: "AMTRELAY",
        261: "Unassigned",
        32768: "TA",
        32769: "DLV",
}
rr_types_bin_str = {x: 0 for x in RR_TYPES.keys()}
rr_types_bin_str[UNKNOWN] = 0


def get_rr_type_str(code):
    if code not in RR_TYPES:
        return UNKNOWN
    return RR_TYPES[code]

# rr bin is an n length binary string
# which records the types that are in a
# dns response


def rr_types_to_bin_str(types):
    rr_types = rr_types_bin_str.copy()
    for t in types:
        if t not in rr_types:
            rr_types[UNKNOWN] = 1
        else:
            rr_types[t] = 1
    # now join the values into a string
    return ''.join([str(x) for x in rr_types.values()])[::-1]


IPv6_NEXT_TYPES = {
    0: "Hop-by-Hop Options Header",
    6: "TCP",
    17: "UDP",
    41: "Encapsulated IPv6 Header",
    43: "Routing Header",
    44: "Fragment Header",
    46: "Resource ReSerVation Protocol",
    50: "Encapsulating Security Payload",
    51: "Authentication Header",
    58: "ICMPv6",
    59: "No next header",
    60: "Destination Options Header"
}


def get_ipv6_next_to_str(t):
    if t not in IPv6_NEXT_TYPES:
        return UNKNOWN
    return IPv6_NEXT_TYPES[t]


TLS_PROTO_VERSION = {
    0x0300: "SSLv3",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

TLS_RECORD_TYPE = {
    20: "SSL3_RT_CHANGE_CIPHER_SPEC",
    21: "SSL3_RT_ALERT",
    22: "SSL3_RT_HANDSHAKE",
    23: "SSL3_RT_APPLICATION_DATA",
    24: "TLS1_RT_HEARTBEAT",
}

TLS_HANDSHAKE_TYPE = {
    0: "HELLO_REQUEST",
    1: "CLIENT_HELLO",
    2: "SERVER_HELLO",
    4: "NEWSESSION_TICKET",
    11: "CERTIFICATE",
    12: "SERVER_KEY_EXCHANGE",
    13: "CERTIFICATE_REQUEST",
    14: "SERVER_DONE",
    15: "CERTIFICATE_VERIFY",
    16: "CLIENT_KEY_EXCHANGE",
    20: "FINISHED",
}

TLS_HEARTBEAT_TYPE = {
    1: "REQUEST",
    2: "RESPONSE"
}

TLS_ALERT_TYPE = {
    1: "WARNING",
    2: "FATAL"
}

TLS_ALERT_VALUES = {
    0: "SSL3_AD_CLOSE_NOTIFY",
    10: "SSL3_AD_UNEXPECTED_MESSAGE",
    20: "SSL3_AD_BAD_RECORD_MAC",
    21: "TLS1_AD_DECRYPTION_FAILED",
    22: "TLS1_AD_RECORD_OVERFLOW",
    30: "SSL3_AD_DECOMPRESSION_FAILURE",
    40: "SSL3_AD_HANDSHAKE_FAILURE",
    41: "SSL3_AD_NO_CERTIFICATE",
    42: "SSL3_AD_BAD_CERTIFICATE",
    43: "SSL3_AD_UNSUPPORTED_CERTIFICATE",
    44: "SSL3_AD_CERTIFICATE_REVOKED",
    45: "SSL3_AD_CERTIFICATE_EXPIRED",
    46: "SSL3_AD_CERTIFICATE_UNKNOWN",
    47: "SSL3_AD_ILLEGAL_PARAMETER",
    48: "TLS1_AD_UNKNOWN_CA",
    49: "TLS1_AD_ACCESS_DENIED",
    50: "TLS1_AD_DECODE_ERROR",
    51: "TLS1_AD_DECRYPT_ERROR",
    60: "TLS1_AD_EXPORT_RESTRICTION",
    70: "TLS1_AD_PROTOCOL_VERSION",
    71: "TLS1_AD_INSUFFICIENT_SECURITY",
    80: "TLS1_AD_INTERNAL_ERROR",
    90: "TLS1_AD_USER_CANCELLED",
    100: "TLS1_AD_NO_RENEGOTIATION",
    110: "TLS1_AD_UNSUPPORTED_EXTENSION",
    111: "TLS1_AD_CERTIFICATE_UNOBTAINABLE",
    112: "TLS1_AD_UNRECOGNIZED_NAME",
    113: "TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE",
    114: "TLS1_AD_BAD_CERTIFICATE_HASH_VALUE",
    115: "TLS1_AD_UNKNOWN_PSK_IDENTITY",
}


def get_tls_version_to_str(v):
    if v not in TLS_PROTO_VERSION:
        return UNKNOWN
    return TLS_PROTO_VERSION[v]


def get_tls_record_type_to_str(t):
    if t not in TLS_RECORD_TYPE:
        return UNKNOWN
    return TLS_RECORD_TYPE[t]


def get_tls_handshake_type_to_str(t):
    if t not in TLS_HANDSHAKE_TYPE:
        return UNKNOWN
    return TLS_HANDSHAKE_TYPE[t]


def get_tls_heartbeat_type(t):
    if t not in TLS_HEARTBEAT_TYPE:
        return UNKNOWN
    return TLS_HEARTBEAT_TYPE[t]


def get_tls_alert_type(t):
    if t not in TLS_ALERT_TYPE:
        return UNKNOWN
    return TLS_ALERT_TYPE[t]

def get_tls_alert_value(v):
    if v not in TLS_ALERT_VALUES:
        return UNKNOWN
    return TLS_ALERT_VALUES[v]
