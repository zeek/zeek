# @TEST-EXEC: zeek -b -r $TRACES/lldp.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

event unknown_protocol(analyzer_name: string, protocol: count, first_bytes: string)
	{ print analyzer_name, protocol, bytestring_to_hexstr(first_bytes); }

