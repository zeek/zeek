# @TEST-EXEC: zeek -b -r $TRACES/ipv6-hbh-routing0.trace %INPUT >output
# @TEST-EXEC: btest-diff output

event ipv6_ext_headers(c: connection, p: pkt_hdr)
	{
	for ( h in p$ip6$exts )
		if ( p$ip6$exts[h]$id == IPPROTO_ROUTING )
			if ( p$ip6$exts[h]$routing$rtype == 0 )
				print routing0_data_to_addrs(p$ip6$exts[h]$routing$data);
	}
