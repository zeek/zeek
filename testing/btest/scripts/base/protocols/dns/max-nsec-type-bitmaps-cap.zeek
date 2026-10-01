# @TEST-DOC: Test dns_NSEC type bitmaps limit

# @TEST-EXEC: zeek -b -C -r $TRACES/dns/udp-nsec-type-bitmaps-cap.pcap %INPUT >output

# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m dns.log
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/protocols/conn
@load base/protocols/dns
@load base/frameworks/notice/weird

event dns_NSEC(c: connection, msg: dns_msg, ans: dns_answer, next_name: string, bitmaps: vector of string)
	{
	print "dns_NSEC", c$uid, |bitmaps|;
	}
