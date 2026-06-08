# @TEST-DOC: Tests the weirds for truncated ICMP6 nd options.
#
# @TEST-EXEC: zeek -C -r $TRACES/icmp/icmp6-nd-short-options.pcap %INPUT
# @TEST-EXEC: btest-diff weird.log

event icmp_router_advertisement(c: connection, info: icmp_info, cur_hop_limit: count, managed: bool, other: bool, home_agent: bool, pref: count, proxy: bool, rsv: count, router_lifetime: interval, reachable_time: interval, retrans_timer: interval, options: icmp6_nd_options)
	{ }

event icmp_neighbor_advertisement(c: connection, info: icmp_info, router: bool, solicited: bool, override: bool, tgt: addr, options: icmp6_nd_options)
	{ }

event icmp_neighbor_solicitation(c: connection, info: icmp_info, tgt: addr, options: icmp6_nd_options)
	{ }

event icmp_redirect(c: connection, info: icmp_info, tgt: addr, dest: addr, options: icmp6_nd_options)
	{ }
