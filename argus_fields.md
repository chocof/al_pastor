smac - Source MAC addr
dmac - Destination MAC addr
rank - Unique record identifier
saddr - Source Address (IPv4,IPv6)
daddr - Destination Address (IPv4,IPv6)
sport - Source Port (Transport Layer)
dport - Destination Port (Transport Layer)
proto - Protocol (Top Layer)
sbytes - #Bytes sent from Source
dbytes - #Bytes sent to Source
spkts - #Packets sent from Source 
dpkts - #Packets sent to Source
dur - Flow duration
state - General transaction state
flgs - Flow state flags seen in transaction.
tcpopt - The TCP connection options seen at initiation
swin - source TCP window advertisement
dwin - destination TCP window advertisement
tcprtt - TCP connection setup round-trip time, the sum of 'synack' and 'ackdat'
synack - TCP connection setup time, the time between the SYN and the SYN_ACK packets
ackdat - TCP connection setup time, the time between the SYN_ACK and the ACK packets
sload - Source bits per second.
dload - Destination bits per second.
sttl - src -> dst TTL value
dttl - dst -> src TTL value
smaxsz - maximum packet size for traffic transmitted by the src
sminsz - minimum packet size for traffic transmitted by the src
dmaxsz - maximum packet size for traffic transmitted by the dst
dminsz - minimum packet size for traffic transmitted by the dst
sappbytes - src -> dst application bytes
dappbytes - dst -> src application bytes
sretrans - source pkts retransmitted
dretrans - destination pkts retransmitted
pretrans - percent pkts retransmitted
psretrans - percent source pkts retransmitted



ra -s srcid -s saddr -s daddr -s sport -s dport -s proto -s sbytes -s dbytes -s spkts -s dpkts -s dur -s state -s flgs -s tcpopt -s swin -s dwin -s tcprtt -s synack -s ackdat -s sload -s dload -s sttl -s dttl -s smaxsz -s sminsz -s dmaxsz -s dminsz -s sappbytes -s dappbytes -s sretrans -s dretrans -s pretrans -s psretrans -r packet.argus

