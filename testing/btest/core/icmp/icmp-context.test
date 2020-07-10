# These tests all check that IPv6 context packet construction for ICMP6 works.

# @TEST-EXEC: zeek -b -r $TRACES/icmp/icmp-destunreach-no-context.pcap %INPUT >>output 2>&1
# @TEST-EXEC: zeek -b -r $TRACES/icmp/icmp-destunreach-ip.pcap %INPUT >>output 2>&1
# @TEST-EXEC: zeek -b -r $TRACES/icmp/icmp-destunreach-udp.pcap %INPUT >>output 2>&1
# @TEST-EXEC: btest-diff output

event icmp_unreachable(c: connection, info: icmp_info, code: count, context: icmp_context)
    {
    print "icmp_unreachable (code=" + fmt("%d", code) + ")";
    print "  conn_id: " + fmt("%s", c$id);
    print "  icmp_info: " + fmt("%s", info);
    print "  icmp_context: " + fmt("%s", context);
    }
