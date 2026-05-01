# @TEST-DOC: tests for ZAM profiling BiFs
#
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
#
# Windows can return 0 for ZAM::Prof::estimated_profiling_overhead().
#
# @TEST-REQUIRES: ! is-windows
#
# @TEST-EXEC: zeek -O ZAM -r $TRACES/wikipedia.pcap %INPUT >output
# @TEST-EXEC: btest-diff output

module MyTest;

global n = 0;
global big_table: table[count] of vector of count;
global v = vector(0, 1, 2, 3, 4, 5, 6, 7, 8, 9);
global last_num_inst = 0;

event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	if ( ++n == 1 )
		{
		local i = 0;
		while ( ++i < 10000 )
			big_table[i] = copy(v);
		}

	else if ( n % 100 == 0 )
		{
		local prof = ZAM::Prof::get_module_profile("MyTest");

		if ( ! prof?$CPU )
			{
			prof$CPU = -1 sec;
			prof$mem = 0;
			}

		# Note, in the following the instruction counts may change due
		# to changes to ZAM code generation such as new optimizations,
		# so we instead just make sure it's monotone increasing.
		#
		# In addition, some OS's don't provide reliable memory stats,
		# so don't try reporting anything about that.
		print fmt("bodies: %d, calls: %d, inst monotone: %s, CPU > 0: %s",
			prof$num_bodies, prof$num_calls,
			prof$num_inst > last_num_inst, prof$CPU > 0 sec);

		if ( n == 200 )
			ZAM::Prof::set_module_profiling("MyTest", F);

		last_num_inst = prof$num_inst;
		}
	}

event zeek_init()
	{
	print fmt("Measurement overhead > 0: %s",
		ZAM::Prof::estimated_profiling_overhead() > 0 sec);
	print fmt("Measuring %d bodies", ZAM::Prof::set_module_profiling("MyTest", T));
	}
