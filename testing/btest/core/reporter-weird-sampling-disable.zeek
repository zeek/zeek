# @TEST-EXEC: zeek -b -r $TRACES/http/bro.org.pcap %INPUT >output
# @TEST-EXEC: btest-diff output

redef Weird::sampling_threshold = 1;
redef Weird::sampling_rate = 0;

event net_weird(name: string)
	{
	print "net_weird", name;
	}

event gen_weirds(c: connection)
	{
	local num = 5;

	while ( num != 0 )
		{
		Reporter::net_weird("my_net_weird");
		--num;
		}
	}

global did_one_connection = F;

event new_connection(c: connection)
	{
	if ( did_one_connection )
		return;

	did_one_connection = T;
	event gen_weirds(c);
	}
