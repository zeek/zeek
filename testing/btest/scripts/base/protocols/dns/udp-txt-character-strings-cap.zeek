# @TEST-DOC: Test dns_TXT_reply character strings limit.

# @TEST-EXEC: zeek -b -C -r $TRACES/dns/udp-txt-character-strings-cap.pcap %INPUT >output

# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m dns.log
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/protocols/conn
@load base/protocols/dns
@load base/frameworks/notice/weird

event dns_TXT_reply(c: connection, msg: dns_msg, ans: dns_answer, strs: vector of string)
	{
	print c$uid, |strs|;
	}
