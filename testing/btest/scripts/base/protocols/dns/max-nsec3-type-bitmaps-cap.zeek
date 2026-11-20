# @TEST-DOC: Test dns_NSEC3 type bitmaps limit

# @TEST-EXEC: zeek -b -C -r $TRACES/dns/udp-nsec3-type-bitmaps-cap.pcap %INPUT >output

# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m dns.log
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/protocols/conn
@load base/protocols/dns
@load base/frameworks/notice/weird

event dns_NSEC3(c: connection, msg: dns_msg, ans: dns_answer, nsec3: dns_nsec3_rr)
	{
	print "dns_NSEC3", c$uid, |nsec3$bitmaps|;
	}
