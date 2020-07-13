# @TEST-EXEC: zeek -b -r $TRACES/tunnels/gre-erspan3-dot1q.pcap %INPUT > out
# @TEST-EXEC: btest-diff out

event icmp_echo_request(c: connection, info: icmp_info, id: count, seq: count, payload: string)
	{
	print "echo request", id, seq;
	}

event icmp_echo_reply(c: connection, info: icmp_info, id: count, seq: count, payload: string)
	{
	print "echo reply", id, seq;
	}

event connection_state_remove(c: connection)
	{
	print c$id;
	print c$tunnel;
	print fmt("vlans %s, %s", c$vlan, c?$inner_vlan ? "shouldn't be set" : "nil");
	}
