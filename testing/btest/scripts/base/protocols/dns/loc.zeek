# @TEST-EXEC: zeek -b -C -r $TRACES/dns/loc-29-trunc.pcap %INPUT > output
# @TEST-EXEC: btest-diff dns.log
# @TEST-EXEC: btest-diff output
@load base/protocols/dns

event dns_LOC(c: connection, msg: dns_msg, ans: dns_answer, loc: dns_loc_rr)
        {
        print "LOC", loc;
        }
