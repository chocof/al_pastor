from common import LAYERS
from field import Field
from layer import (ARP_Layer, DHCP_Layer, DNS_Layer, ETH_Layer, ICMP_Layer,
                   IP_Layer, IPv6_Layer, TCP_Layer, TLS_Layer, UDP_Layer)


class Packet:
    def __init__(self, p):
        self._idx = int(p.number)
        self._proto = p.highest_layer
        self._verdict = None
        self._layers = []
        self._fields = []
        self.notes = []
        self._assign_frame_info(p)
        self._parse_layers(p)

    def get_idx(self):
        return self._idx

    def assign_snort_verdict(self, v):
        self._verdict = v

    def attention(self, ):
        return self._verdict.is_important() if self._verdict else False

    def get_layers_str(self,):
        return "_".join([l.get_name() for l in self._layers])

    def get_csv_fields(self,):
        fields = {}
        for l in self._layers:
            layer_fields = l.get_fields()
            for f in layer_fields:
                if f.add_to_csv():
                    fields["{}_{}".format(l.get_name(), f.get_key())] = f.get_value()
        fields["severity"] = self._verdict.get_priority()
        return fields

    def _assign_frame_info(self, p):
        self._fields.append(Field(p.frame_info, 'cap_len'))
        self._fields.append(Field(p.frame_info, 'ignored'))
        self._fields.append(Field(p.frame_info, 'marked'))
        self._fields.append(Field(p.frame_info, 'time_epoch', t=float))
        self._fields.append(Field(p.frame_info, 'encap_type'))

    def _parse_layers(self, p):
        layer_factory = {
            LAYERS.ETH: ETH_Layer,
            LAYERS.ARP: ARP_Layer,
            LAYERS.DCHP: DHCP_Layer,
            LAYERS.DNS: DNS_Layer,
            LAYERS.IP: IP_Layer,
            LAYERS.IPV6: IPv6_Layer,
            LAYERS.ICMP: ICMP_Layer,
            LAYERS.UDP: UDP_Layer,
            LAYERS.TCP: TCP_Layer,
            LAYERS.TLS: TLS_Layer,
        }
        for l in p.layers:
            # if this layer is implemented then add it into the list
            if l.layer_name in layer_factory:
                new_layer = layer_factory[l.layer_name](l)
                self._layers.append(new_layer)
            else:
                self.notes.append('Skipped Layer {}'.format(l.layer_name))
