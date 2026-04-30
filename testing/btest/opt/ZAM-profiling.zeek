# @TEST-DOC: tests for ZAM profiling BiFs
#
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
#
# @TEST-EXEC: zeek -O ZAM -r $TRACES/wikipedia.pcap %INPUT >output
# @TEST-EXEC: btest-diff output

module MyTest;

global n = 0;
global big_table: table[count] of vector of count;
global v = vector(0, 1, 2, 3, 4, 5, 6, 7, 8, 9);

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
		local prof = ZAMProf::get_module_profile("MyTest");

		if ( ! prof?$CPU )
			{
			prof$CPU = -1 sec;
			prof$mem = 0;
			}

		# Note, in the following the instruction counts may change due
		# to changes to ZAM code generation such as new optimizations.
		print fmt("bodies: %d, calls: %d, inst: %d, CPU > 0: %s, memory > 500KB = %s",
			prof$num_bodies, prof$num_calls, prof$num_inst,
			prof$CPU > 0 sec, prof$mem > 500000);

		if ( n == 200 )
			ZAMProf::measure_module("MyTest", F);
		}
	}

event zeek_init()
	{
	print fmt("Measurement overhead > 0: %s", ZAMProf::meas_overhead() > 0 sec);
	print fmt("Measuring %d bodies", ZAMProf::measure_module("MyTest", T));
	}
