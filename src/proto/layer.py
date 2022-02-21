from field import Field
from common import get_eth_type_str, get_tls_handshake_type_to_str, \
    get_ipv6_next_to_str, get_tls_version_to_str

class Layer:
    """
    this is the layer representation in our syste
    contains the subset of information that we shall store
    from each network layer
    """
    def __init__(self, l, pl):
        self.name = l.layer_name
        self.previous_layer = pl
        self._fields = []
        self.sport = None
        self.dport = None
        self.sip = None
        self.dip = None
        self.argus_proto_name = None

    def get_previous_layer(self,):
        return self.pl 

    def get_argus_proto_name(self):
        return self.argus_proto_name
        
    def set_argus_proto_name(self, apn):
        self.argus_proto_name = apn

    def get_ports(self,):
        return self.sport, self.dport

    def set_ports(self, sport, dport):
        self.sport = sport.get_value()
        self.dport = dport.get_value()
        
    def get_ips(self,):
        return self.sip, self.dip

    def set_ips(self,sip, dip):
        self.sip = sip.get_value()
        self.dip = dip.get_value()
        
    def get_name(self,):
        return self.name
    def get_fields(self):
        return self._fields
    def get_field_value(self,):
        pass


class ETH_Layer(Layer):
    def __init__(self, l, pl):
        super().__init__(l, pl)
        # no need to include src and dst to csv
        # we are not performing mac addr blacklisting yet
        self._fields.append(Field(l, 'src', to_csv=False, t=str))
        self._fields.append(Field(l, 'dst', to_csv=False, t=str))
        self._fields.append(Field(l, 'type', b=16, to_str=get_eth_type_str))


class ARP_Layer(Layer):
    def __init__(self, l, pl):
        super().__init__(l, pl)
        self.set_argus_proto_name('arp')
        self._fields.append(Field(l, 'hw_type')) 
        self._fields.append(Field(l, 'proto_type', b=16)) 
        self._fields.append(Field(l, 'hw_size')) 
        self._fields.append(Field(l, 'proto_size')) 
        self._fields.append(Field(l, 'opcode')) 

class DHCP_Layer(Layer):
    def __init__(self, l, pl):
        super().__init__(l, pl)
        self._fields.append(Field(l, 'hw_type', b=16))
        self._fields.append(Field(l, 'hw_len'))
        self._fields.append(Field(l, 'hops'))
        self._fields.append(Field(l, 'secs'))
        self._fields.append(Field(l, 'flags_bc'))
        self._fields.append(Field(l, 'flags_reserved', b=16))
        self._fields.append(Field(l, 'option_type'))
        self._fields.append(Field(l, 'option_length'))
        self._fields.append(Field(l, 'option_value'))
        self._fields.append(Field(l, 'option_dhcp'))
        self._fields.append(Field(l, 'option_request_list_item'))
        self._fields.append(Field(l, 'option_end'))

class DNS_Layer(Layer):
    def __init__(self, l, pl):
        super().__init__(l, pl)
        self._fields.append(Field(l, 'flags_response')) 
        self._fields.append(Field(l, 'flags_opcode')) 
        self._fields.append(Field(l, 'flags_truncated')) 
        self._fields.append(Field(l, 'flags_recdesired')) 
        self._fields.append(Field(l, 'flags_z')) 
        self._fields.append(Field(l, 'flags_checkdisable')) 
        
        self._fields.append(Field(l, 'count_queries')) 
        self._fields.append(Field(l, 'count_answers')) 
        self._fields.append(Field(l, 'count_auth_rr')) 
        self._fields.append(Field(l, 'count_add_rr')) 
        
        self._fields.append(Field(l, 'qry_class', b=16)) 
        self._fields.append(Field(l, 'qry_name_len')) 
        self._fields.append(Field(l, 'count_labels'))
        self._fields.append(Field(l, 'qry_type')) 

class IP_Layer(Layer):
    def __init__(self, l, pl):
        super().__init__(l, pl)
        # no need to include src and dst to csv
        # we are not performing ip addr blacklisting yet
        src_ip = Field(l, 'src', t=str, to_csv=False)
        self._fields.append(src_ip)
        dst_ip = Field(l, 'dst', t=str, to_csv=False)
        self._fields.append(dst_ip)
        self.set_ips(src_ip, dst_ip)
        self._fields.append(Field(l, 'checksum_status'))
        self._fields.append(Field(l, 'ttl'))
        self._fields.append(Field(l, 'proto'))
        self._fields.append(Field(l, 'flags_rb'))
        self._fields.append(Field(l, 'flags_df'))
        self._fields.append(Field(l, 'flags_mf'))
        self._fields.append(Field(l, 'frag_offset'))
        self._fields.append(Field(l, 'dsfield_dscp'))
        self._fields.append(Field(l, 'dsfield_ecn'))
        self._fields.append(Field(l, 'hdr_len'))
        self._fields.append(Field(l, 'len'))

class IPv6_Layer(Layer):
    def __init__(self, l, pl):
        super().__init__(l, pl)
        self.set_argus_proto_name('ipv6_icmp')
        # no need to include src and dst to csv
        # we are not performing ip addr blacklisting yet
        src_ip = Field(l, 'src', t=str, to_csv=False)
        self._fields.append(src_ip)
        dst_ip = Field(l, 'dst', t=str, to_csv=False)
        self._fields.append(dst_ip)
        self.set_ips(src_ip, dst_ip)
        self._fields.append(Field(l, 'tclass', b=16))
        self._fields.append(Field(l, 'tclass_dscp', b=16))
        self._fields.append(Field(l, 'tclass_ecn', b=16))
        self._fields.append(Field(l, 'plen'))
        self._fields.append(Field(l, 'next', to_str=get_ipv6_next_to_str))
        self._fields.append(Field(l, 'hlim'))
        self._fields.append(Field(l, 'flow', b=16))


class ICMP_Layer(Layer):
    def __init__(self, l, pl):
        super().__init__(l, pl)
        if isinstance(pl, IPv6_Layer):
            self.set_argus_proto_name('ipv6-icmp')
        else:
            self.set_argus_proto_name('icmp')
        self._fields.append(Field(l, 'code'))
        self._fields.append(Field(l, 'type'))
        self._fields.append(Field(l, 'checksum_status'))
        
class UDP_Layer(Layer):
    def __init__(self, l, pl):
        super().__init__(l, pl)
        self.set_argus_proto_name('udp')
        srcport = Field(l, 'srcport')
        self._fields.append(srcport)
        dstport = Field(l, 'dstport')
        self._fields.append(dstport)
        self.set_ports(srcport, dstport)
        self.set_ports(srcport, dstport)

        self._fields.append(Field(l, 'len'))
        self._fields.append(Field(l, 'time_relative', t=float))
        self._fields.append(Field(l, 'time_delta', t=float))


class TCP_Layer(Layer):
    def __init__(self, l, pl):
        super().__init__(l, pl)
        self.set_argus_proto_name('tcp')
        srcport = Field(l, 'srcport')
        self._fields.append(srcport)
        dstport = Field(l, 'dstport')
        self._fields.append(dstport)
        self.set_ports(srcport, dstport)
        self._fields.append(Field(l, 'len'))
        self._fields.append(Field(l, 'seq'))
        self._fields.append(Field(l, 'ack'))
        self._fields.append(Field(l, 'nxtseq'))
        self._fields.append(Field(l, 'hdr_len'))
        self._fields.append(Field(l, 'flags_res'))
        self._fields.append(Field(l, 'flags_ns'))
        self._fields.append(Field(l, 'flags_cwr'))
        self._fields.append(Field(l, 'flags_ecn'))
        self._fields.append(Field(l, 'flags_urg'))
        self._fields.append(Field(l, 'flags_ack'))
        self._fields.append(Field(l, 'flags_push'))
        self._fields.append(Field(l, 'flags_reset'))
        self._fields.append(Field(l, 'flags_syn'))
        self._fields.append(Field(l, 'flags_fin'))
        self._fields.append(Field(l, 'window_size_value'))
        self._fields.append(Field(l, 'window_size_scalefactor'))
        self._fields.append(Field(l, 'checksum_status'))
        self._fields.append(Field(l, 'urgent_pointer'))
        self._fields.append(Field(l, 'time_relative', t=float))
        self._fields.append(Field(l, 'time_delta', t=float))
        self._parse_options(l)

    def _parse_options(self, l):
        self._fields.append(Field(l, 'option_kind'))
        self._fields.append(Field(l, 'option_len'))
        self._fields.append(Field(l, 'options_mss_val'))
        self._fields.append(Field(l, 'options_wscale_shift'))
        self._fields.append(Field(l, 'options_wscale_multiplier'))
        self._fields.append(Field(l, 'options_timestamp_tsval'))
        self._fields.append(Field(l, 'options_timestamp_tsecr'))
        self._fields.append(
            Field(l, 'options_sack_perm', store_existance=True))
        self._fields.append(Field(l, 'options_eol', store_existance=True))
        self._fields.append(Field(l, 'options_nop', store_existance=True))

class QUIC_LAYER(Layer):
    def __init__(self, l, pl):
        pass
class HTTP_Layer(Layer):
    def __init__(self, l, pl):
        super().__init__(l, pl)


class TLS_Layer(Layer):
    def __init__(self, l, pl):
        super().__init__(l, pl)
        self._fields.append(Field(l, 'record_type'))
        self._fields.append(Field(l, 'record_length'))
        self._fields.append(Field(l, 'record_version', b=16, to_str=get_tls_version_to_str))
        self._handle_handshake(l)

    def _handle_handshake(self, l):
        # client/server hello
        self._fields.append(Field(l, 'handshake_type', to_str=get_tls_handshake_type_to_str))
        self._fields.append(Field(l, 'handshake_length'))
        self._fields.append(Field(l, 'handshake_version', to_str=get_tls_version_to_str, b=16))
        self._fields.append(Field(l, 'handshake_random', store_existance=True))
        self._fields.append(Field(l, 'handshake_session_id_length'))
        self._fields.append(Field(l, 'handshake_cipher_suites_length'))
        self._fields.append(Field(l, 'handshake_ciphersuite', b=16))
        self._fields.append(Field(l, 'handshake_comp_methods_length'))
        self._fields.append(Field(l, 'handshake_comp_method'))
        self._fields.append(Field(l, 'handshake_extension_type'))
        self._fields.append(Field(l, 'handshake_extension_len'))
        self._fields.append(Field(l, 'handshake_extensions_supported_groups_length'))
        self._fields.append(Field(l, 'handshake_extensions_supported_group', b=16))
        self._fields.append(Field(l, 'handshake_extensions_ec_point_formats_length'))
        self._fields.append(Field(l, 'handshake_extensions_ec_point_format'))
        self._fields.append(Field(l, 'handshake_sig_hash_alg_len'))
        self._fields.append(Field(l, 'handshake_sig_hash_alg', b=16))
        self._fields.append(Field(l, 'handshake_extensions_key_share_client_length'))
        self._fields.append(Field(l, 'handshake_extensions_key_share_group', b=16))
        self._fields.append(Field(l, 'handshake_extensions_key_share_key_exchange_length'))
        self._fields.append(Field(l, 'handshake_extensions_supported_versions_len'))
        self._fields.append(Field(l, 'handshake_extensions_supported_version', b=16))
        # server hello
        self._fields.append(Field(l, 'handshake_server_curve_type', b=16))
        self._fields.append(Field(l, 'handshake_server_named_curve', b=16))
        self._fields.append(Field(l, 'handshake_server_point_len',))
        # session ticket
        self._fields.append(Field(l, 'handshake_session_ticket_length'))
        self._fields.append(Field(l, 'handshake_session_ticket_lifetime_hint'))
        # TODO check other handshake types
