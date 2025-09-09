# @TEST-DOC: Tests that a DNS dynamic update packet is processed.
# @TEST-EXEC: zeek -b -C -r $TRACES/dns/dynamic-update.pcap %INPUT >out 2>&1
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: ! test -f weird.log

@load base/frameworks/notice/weird
@load base/protocols/dns

event dns_dynamic_update(c: connection, msg: dns_msg, zname: string, zclass: count)
	{
	print msg, zname, zclass, DNS::classes[zclass];
	}
