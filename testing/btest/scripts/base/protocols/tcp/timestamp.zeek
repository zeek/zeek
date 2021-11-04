# @TEST-EXEC: zeek -b -C -r $TRACES/tcp/timestamp.pcap %INPUT
# @TEST-EXEC: btest-diff .stdout

event connection_SYN_packet(c: connection, pkt: SYN_packet) {
        print pkt;
}
