# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

# In old version, the event would keep triggering endlessly, with the network
# time not moving forward and Zeek not terminating.

redef exit_only_after_terminate=T;

global c = 0;
global last_nt = 0.0;
global unique_nt: set[double];

event test()
        {
	c += 1;
	local nt = time_to_double(network_time());
	if ( last_nt == 0.0 )
		last_nt = nt;

	add unique_nt[nt];

	print fmt("%.5f %d %d", nt, nt != last_nt, c);
	last_nt = nt;

	if ( c == 20 )
		{
		print fmt("unique_nt %d", |unique_nt|);
		terminate();
		return;
		}

	event test();
	}

event zeek_init()
	{
	event test();
	}
