# @TEST-EXEC: zeek -b -r $TRACES/http/bro.org.pcap %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff config.log

@load base/frameworks/config

event zeek_init()
	{
	Config::set_value("Weird::sampling_duration", 5sec);
	Config::set_value("Weird::sampling_threshold", 10);
	Config::set_value("Weird::sampling_rate", 10);
	Config::set_value("Weird::sampling_whitelist", set("whitelisted_net_weird", "whitelisted_flow_weird", "whitelisted_conn_weird"));
	print "Config values set";
	}

event zeek_init() &priority = -10
	{
	local v: vector of string = vector();
	local wl = Reporter::get_weird_sampling_whitelist();

	for ( e in wl )
		v += e;

	sort(v, strcmp);
	print v;
	print Reporter::get_weird_sampling_rate();
	print Reporter::get_weird_sampling_threshold();
	print Reporter::get_weird_sampling_duration();
	}

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

		Reporter::net_weird("whitelisted_net_weird");
		Reporter::flow_weird("whitelisted_flow_weird", c$id$orig_h, c$id$resp_h);
		Reporter::conn_weird("whitelisted_conn_weird", c);
		--num;
		}
	}

global did_one_connection = F;

event new_connection(c: connection)
	{
	if ( did_one_connection )
		return;

	did_one_connection = T;
	event gen_weirds(c);             # should permit 10 + 2 of each "my" weird
	schedule 2sec { gen_weirds(c) }; # should permit 3 of each "my" weird
	schedule 7sec { gen_weirds(c) }; # should permit 10 + 2 of each "my" weird
	# Total of 27 "my" weirds of each type and 90 of each "whitelisted" type
	}
