# @TEST-DOC: Verifies zeek_invalid_checksums_total telemetry metric across failure, pass, drop, and ignore modes.
#
# 1. Corrupted checksum fixtures (IPv4)
# @TEST-EXEC: zeek -b -r $TRACES/chksums/ip4-bad-chksum.pcap %INPUT >out-ipv4
# @TEST-EXEC: zeek -b -r $TRACES/chksums/ip4-tcp-bad-chksum.pcap %INPUT >out-tcp
# @TEST-EXEC: zeek -b -r $TRACES/chksums/ip4-udp-bad-chksum.pcap %INPUT >out-udp
# @TEST-EXEC: zeek -b -r $TRACES/chksums/ip4-icmp-bad-chksum.pcap %INPUT >out-icmp
# @TEST-EXEC: zeek -b -r $TRACES/chksums/mip6-bad-mh-chksum.pcap %INPUT >out-mobility
#
# 2. Corrupted checksum fixtures (IPv6)
# @TEST-EXEC: zeek -b -r $TRACES/chksums/ip6-tcp-bad-chksum.pcap %INPUT >out-ipv6-tcp
# @TEST-EXEC: zeek -b -r $TRACES/chksums/ip6-udp-bad-chksum.pcap %INPUT >out-ipv6-udp
# @TEST-EXEC: zeek -b -r $TRACES/chksums/ip6-icmp6-bad-chksum.pcap %INPUT >out-ipv6-icmp
#
# 3. Valid checksum fixtures (all counters remain zero)
# @TEST-EXEC: zeek -b -r $TRACES/chksums/ip4-tcp-good-chksum.pcap %INPUT >out-good
#
# 4. Ignored checksums (-C and ignore_checksums_nets -> all counters remain zero)
# @TEST-EXEC: zeek -b -C -r $TRACES/chksums/ip4-tcp-bad-chksum.pcap %INPUT >out-cli-ignore
# @TEST-EXEC: zeek -b -r $TRACES/chksums/localhost-bad-chksum.pcap "ignore_checksums_nets += {127.0.0.0/8}" %INPUT >out-subnet-ignore
#
# 5. Active drop mode (counters increment even when packets are dropped)
# @TEST-EXEC: zeek -b -r $TRACES/chksums/ip4-tcp-bad-chksum.pcap %INPUT drop_bad_checksums=T >out-drop
#
# 6. Baseline comparisons
# @TEST-EXEC: btest-diff out-ipv4
# @TEST-EXEC: btest-diff out-tcp
# @TEST-EXEC: btest-diff out-udp
# @TEST-EXEC: btest-diff out-icmp
# @TEST-EXEC: btest-diff out-mobility
# @TEST-EXEC: btest-diff out-ipv6-tcp
# @TEST-EXEC: btest-diff out-ipv6-udp
# @TEST-EXEC: btest-diff out-ipv6-icmp
# @TEST-EXEC: btest-diff out-good
# @TEST-EXEC: btest-diff out-cli-ignore
# @TEST-EXEC: btest-diff out-subnet-ignore
# @TEST-EXEC: btest-diff out-drop

@load base/frameworks/telemetry

redef running_under_test = T;

event zeek_done() {
    local metrics = Telemetry::collect_metrics("zeek", "invalid_checksums*");
    local counts: table[string] of double = table();

    for ( i in metrics ) {
        local m = metrics[i];
        if ( m$opts$metric_type == Telemetry::COUNTER && |m$label_values| > 0 )
            counts[m$label_values[0]] = m$value;
    }

    local checksum_types = vector(
        "ipv4", "tcp", "udp", "icmp", "mobility"
    );

    for ( i in checksum_types ) {
        local checksum_type = checksum_types[i];
        local val = checksum_type in counts ? counts[checksum_type] : 0.0;
        print fmt("%s = %0.0f", checksum_type, val);
    }
}
