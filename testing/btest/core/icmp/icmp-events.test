# These tests all check that ICMP6 events get raised with correct arguments.

# @TEST-EXEC: zeek -b -r $TRACES/icmp/icmp-destunreach-udp.pcap %INPUT >>output 2>&1
# @TEST-EXEC: zeek -b -r $TRACES/icmp/icmp-timeexceeded.pcap %INPUT >>output 2>&1
# @TEST-EXEC: zeek -b -r $TRACES/icmp/icmp-ping.pcap %INPUT >>output 2>&1

# @TEST-EXEC: btest-diff output

event icmp_sent(c: connection, info: icmp_info)
    {
    print "icmp_sent";
    print "  conn_id: " + fmt("%s", c$id);
    print "  icmp_info: " + fmt("%s", info);
    }

event icmp_echo_request(c: connection, info: icmp_info, id: count, seq: count, payload: string)
    {
    print "icmp_echo_request (id=" + fmt("%d", id) + ", seq=" + fmt("%d", seq) + ", payload=" + payload + ")";
    print "  conn_id: " + fmt("%s", c$id);
    print "  icmp_info: " + fmt("%s", info);
    }

event icmp_echo_reply(c: connection, info: icmp_info, id: count, seq: count, payload: string)
    {
    print "icmp_echo_reply (id=" + fmt("%d", id) + ", seq=" + fmt("%d", seq) + ", payload=" + payload + ")";
    print "  conn_id: " + fmt("%s", c$id);
    print "  icmp_info: " + fmt("%s", info);
    }

event icmp_unreachable(c: connection, info: icmp_info, code: count, context: icmp_context)
    {
    print "icmp_unreachable (code=" + fmt("%d", code) + ")";
    print "  conn_id: " + fmt("%s", c$id);
    print "  icmp_info: " + fmt("%s", info);
    print "  icmp_context: " + fmt("%s", context);
    }

event icmp_time_exceeded(c: connection, info: icmp_info, code: count, context: icmp_context)
    {
    print "icmp_time_exceeded (code=" + fmt("%d", code) + ")";
    print "  conn_id: " + fmt("%s", c$id);
    print "  icmp_info: " + fmt("%s", info);
    print "  icmp_context: " + fmt("%s", context);
    }
