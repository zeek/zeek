# @TEST-DOC: Verify connections can be be looked up using lookup_connection() when using vlan aware conn_id's
#
# The test pcap has 3 overlapping healthy TCP connections, each with different VLAN tagging: none, one VLAN tag, two VLAN tags.
# To create: tcprewrite --enet-vlan=add --enet-vlan-tag 20 --enet-vlan-cfi=1 --enet-vlan-pri=2 -i in.pcap -o out.pcap
#
# @TEST-EXEC: zeek -r $TRACES/vlan-collisions.pcap %INPUT
# @TEST-EXEC: zeek-cut -m ts uid id.orig_h id.orig_p id.resp_h id.resp_p id.ctx.vlan id.ctx.inner_vlan orig_pkts resp_pkts service <conn.log >conn.log.cut
#
# @TEST-EXEC: btest-diff conn.log.cut
# @TEST-EXEC: btest-diff .stderr

@load frameworks/conn_key/vlan_fivetuple

event new_connection(c: connection)
	{
	local c1 = lookup_connection(c$id);
	local c2 = lookup_connection(copy(c$id));

	local c3_id = conn_id($orig_h=c$id$orig_h, $orig_p=c$id$orig_p,
	                      $resp_h=c$id$resp_h, $resp_p=c$id$resp_p,
	                      $ctx=copy(c$id$ctx));
	local c3 = lookup_connection(c3_id);

	# Ensure all the uids are the same!
	assert c$uid == c1$uid && c1$uid == c2$uid && c2$uid == c3$uid;
	}

event new_connection(c: connection)
	{
	assert connection_exists(c$id);

	local nx_id = copy(c$id);
	nx_id$ctx = copy(c$id$ctx);
	nx_id$ctx$vlan = 1000;
	nx_id$ctx$inner_vlan = 2000;
	assert ! connection_exists(nx_id);
	}
