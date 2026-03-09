# @TEST-DOC: Does setting network trigger timer expiration? It should.
# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

redef allow_network_time_forward = F;

# If this is F, we don't enter the IO loop :-(
redef exit_only_after_terminate = T;

event timer(s: string) {
	print network_time(), "timer", s;
	if ( /first timer/ in s )
		{
		print network_time(), "updating network time to 3.5";
		set_network_time(double_to_time(4.0));
		}

	if ( /second timer/ in s )
		{
		print network_time(), "calling terminate()";
		terminate();
		}
}

event zeek_init()
	{
	print network_time(), "zeek_init (1)";
	schedule 1sec { timer("first timer 1.0") };
	set_network_time(double_to_time(1.5));
	}

event zeek_init() &priority=-1
	{
	print network_time(), "zeek_init (2)";
	# This runs at network_time=1.5, so the timer is scheduled
	# at network_time 3.5 seconds (which the first timer will
	# move towards).
	schedule 2sec { timer("second timer") };

	# This is expired after net_done() because it ends
	# up at 4.5 seconds and time is not moved that far.
	schedule 3sec { timer("third timer") };
	set_network_time(double_to_time(2.5));
	}

event net_done(t: time)
	{
	print network_time(), "net_done", t;
	}

event zeek_done()
	{
	print network_time(), "zeek_done";
	}
