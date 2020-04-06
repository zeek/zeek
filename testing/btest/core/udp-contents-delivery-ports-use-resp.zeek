# @TEST-EXEC: zeek -b -r $TRACES/rpc-portmap-sadmind.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

redef udp_content_delivery_ports_use_resp = T;
redef udp_content_delivery_ports_orig += {[54790/udp] = T};
redef udp_content_delivery_ports_resp += {[54790/udp] = T};
redef likely_server_ports += {54790/udp};

event udp_contents(c: connection, is_orig: bool, contents: string)
	{
	print "Contents:", c$id, is_orig, |contents|;
	}
