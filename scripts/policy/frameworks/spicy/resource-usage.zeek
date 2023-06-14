##! Logs Spicy-related resource usage continuously for debugging purposes.

module Spicy;

event print_usage()
	{
	local r = Spicy::resource_usage();

	print fmt("%.6f Spicy user=%f sys=%f heap=%d current_fibers=%d cached_fibers=%d max_fibers=%d max_stack=%d",
	    network_time(), r$user_time, r$system_time, r$memory_heap,
	    r$num_fibers, r$cached_fibers, r$max_fibers,
	    r$max_fiber_stack_size);

	schedule 1 min { print_usage() };
	}

event zeek_init()
	{
	schedule 1 min { print_usage() };
	}
