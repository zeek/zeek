# @TEST-DOC: Verify VLAN-aware flow tuples on colliding traffic.
#
# The test pcap has 3 overlapping healthy TCP connections, each with different VLAN tagging: none, one VLAN tag, two VLAN tags.
# To create: tcprewrite --enet-vlan=add --enet-vlan-tag 20 --enet-vlan-cfi=1 --enet-vlan-pri=2 -i in.pcap -o out.pcap
#
# @TEST-EXEC: zeek -r $TRACES/vlan-collisions.pcap %INPUT
# @TEST-EXEC: zeek-cut -m ts uid id.orig_h id.orig_p id.resp_h id.resp_p id.ctx.vlan id.ctx.inner_vlan orig_pkts resp_pkts service <conn.log >conn.log.cut
# @TEST-EXEC: btest-diff conn.log.cut

# Default operation: Zeek isn't VLAN-aware, a single conn.log entry results.

# @TEST-START-NEXT

# Switch to VLAN-aware flow tuples: multiple conn.log entries with full
# information.

@load frameworks/conn_key/vlan_fivetuple

# @TEST-START-NEXT

# Leave out the conn_id redef: Zeek still distinguishes flows so multiple
# conn.log entries result, but conn.log doesn't show the VLAN fields.

redef ConnKey::factory = ConnKey::CONNKEY_VLAN_FIVETUPLE;

# @TEST-START-NEXT

# Add an extra field before the VLAN ones, to throw off any fixed-offset code.

redef record conn_id_ctx += {
	foo: int &default=1;
};

@load frameworks/conn_key/vlan_fivetuple

# @TEST-START-NEXT

# Add the right fields, but in a different order. (zeek-cut obscures the difference.)

redef record conn_id_ctx += {
	inner_vlan: int &log &optional;
	vlan: int &log &optional;
};

redef ConnKey::factory = ConnKey::CONNKEY_VLAN_FIVETUPLE;

# @TEST-START-NEXT

# Add the right fields, but with the wrong types.

redef record conn_id_ctx += {
	vlan: string &log &optional;
	inner_vlan: string &log &optional;
};

redef ConnKey::factory = ConnKey::CONNKEY_VLAN_FIVETUPLE;
