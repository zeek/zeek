# @TEST-EXEC: zeek -b -r $TRACES/tcp/qi_internet_SYNACK_curl_jsonip.pcap %INPUT
# @TEST-EXEC: btest-diff .stdout

# Quantum Insert like attack, overlapping TCP packet with different content
redef tcp_max_old_segments = 10;
event rexmit_inconsistency(c: connection, t1: string, t2: string, tcp_flags: string)
    {
    print "----- rexmit_inconsistency -----";
    print fmt("%.6f c: %s", network_time(), c$id);
    print fmt("%.6f t1: %s", network_time(), t1);
    print fmt("%.6f t2: %s", network_time(), t2);
    print fmt("%.6f tcp_flags: %s", network_time(), tcp_flags);
    }
