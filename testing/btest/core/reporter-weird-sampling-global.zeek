# @TEST-EXEC: zeek -C -b -r $TRACES/wlanmon.pcap %INPUT | awk '{print $1, $2}' | sort | uniq -c >output
# @TEST-EXEC: btest-diff output

# The sampling functionality itself is already tested through other tests.
# Here, we just set the parameters so that we see a difference between global
# and non-global, using some smooth numbers not affected by rate or timing.
redef Weird::sampling_duration = 300days;
redef Weird::sampling_threshold = 10;
redef Weird::sampling_rate = 0;
redef Weird::sampling_global_list = set("global_listed_net_weird",
                                      "global_listed_flow_weird",
                                      "global_listed_conn_weird");

event conn_weird(name: string, c: connection, addl: string)
	{
	print "conn_weird", name;
	}

event flow_weird(name: string, src: addr, dst: addr, addl: string)
	{
	print "flow_weird", name;
	}

event net_weird(name: string, addl: string)
	{
	print "net_weird", name;
	}

event gen_weirds(c: connection)
	{
	local num = 30;

	while ( num != 0 )
		{
		Reporter::net_weird("my_net_weird");
		Reporter::flow_weird("my_flow_weird", c$id$orig_h, c$id$resp_h);
		Reporter::conn_weird("my_conn_weird", c);

		Reporter::net_weird("global_listed_net_weird");
		Reporter::flow_weird("global_listed_flow_weird", c$id$orig_h, c$id$resp_h);
		Reporter::conn_weird("global_listed_conn_weird", c);
		--num;
		}
	}

global flows: set[addr, addr];

event new_connection(c: connection)
	{
	if ( [c$id$orig_h, c$id$resp_h] in flows )
		return;

	add flows[c$id$orig_h, c$id$resp_h];

	if ( |flows| > 2 )
		return;

	event gen_weirds(c);
	}
