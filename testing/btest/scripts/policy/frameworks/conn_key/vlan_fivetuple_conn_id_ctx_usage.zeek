# @TEST-DOC: Demo for using conn_id$ctx in a table to track HTTP request methods per originator IP and their context.
#
# The test pcap has 3 overlapping healthy TCP connections, each with different VLAN tagging: none, one VLAN tag, two VLAN tags.
# To create: tcprewrite --enet-vlan=add --enet-vlan-tag 20 --enet-vlan-cfi=1 --enet-vlan-pri=2 -i in.pcap -o out.pcap
#
# @TEST-EXEC: zeek -b -r $TRACES/vlan-collisions.pcap base/protocols/http ./count-http-request-methods.zeek %INPUT >out
# @TEST-EXEC: btest-diff out

# Default operation: Zeek isn't VLAN-aware, a single conn.log entry results.

# @TEST-START-NEXT

# Switch to VLAN-aware flow tuples: multiple conn.log entries with full
# information.

@load frameworks/conn_key/vlan_fivetuple

# @TEST-START-FILE count-http-request-methods.zeek
global http_requests: table[addr, conn_id_ctx, string] of count &default=0;

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
	{
	++http_requests[c$id$orig_h, c$id$ctx, method];
	}

event zeek_done()
	{
	for ( [h, ctx, method], c in http_requests )
		print h, ctx, method, c;
	}
# @TEST-END-FILE
