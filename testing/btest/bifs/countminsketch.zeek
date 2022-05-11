# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

global exact: table[count] of count = table();

function print_test_result(c: opaque of countminsketch, v: count)
	{
	if ( v ! in exact )
		return;

	print fmt("Exact: %d, estimate: %d", exact[v], count_min_sketch_estimate(c, v));
	}

event zeek_init()
	{
	local cms = count_min_sketch_advanced_init(2000, 10);

  local i : count = 0;
	while ( i < 10000 )
		{
		local randvalue = rand(1000);
		count_min_sketch_update(cms, randvalue);
		if ( randvalue in exact )
			exact[randvalue] += 1;
		else
			exact[randvalue] = 1;
		i += 1;
		#if ( i % 1000 == 0 )
		#	print i;
		}

	print_test_result(cms, 7);
	print_test_result(cms, 77);
	}
