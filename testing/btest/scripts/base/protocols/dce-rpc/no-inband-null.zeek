# @TEST-DOC: If there is no in-band null character, ensure payload is not trimmed
#
# @TEST-EXEC: zeek -r $TRACES/dce-rpc/bind-ack-no-inband-null.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

event dce_rpc_bind_ack(c: connection, fid: count, sec_addr: string)
	{
	print fmt("sec_addr is: %s", sec_addr);
	}
