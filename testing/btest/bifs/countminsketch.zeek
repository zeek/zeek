# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

global exact: table[count] of count = table();

function print_test_result(c: opaque of countminsketch, v: count)
	{
	if ( v ! in exact )
		return;

	print fmt("Exact: %d, estimate: %d", exact[v], count_min_sketch_estimate(c, v));
	}

function advanced_test()
	{
	local cms = count_min_sketch_advanced_init(2000, 10);
	exact = table();

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
	print "Total observations", count_min_sketch_get_total(cms);
	}

function advanced_test_two()
	{
	local cms = count_min_sketch_advanced_init(2719, 7);
	exact = table();

  local i : count = 0;
	while ( i < 10000 )
		{
		local randvalue = rand(10000);
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
	print "Total observations", count_min_sketch_get_total(cms);
	}

function merge_test()
	{
	local cms = count_min_sketch_advanced_init(2719, 7);
	local cms_two = copy(cms); # copy of empty cms to get same random number initialization
	count_min_sketch_update(cms, 0, 10);
	count_min_sketch_update(cms, 42, 11);
	count_min_sketch_update(cms_two, 42, 250);
	count_min_sketch_update(cms_two, 88, 11);
	print count_min_sketch_estimate(cms, 0);
	print count_min_sketch_estimate(cms, 42);
	print count_min_sketch_estimate(cms, 88);
	local new = count_min_sketch_merge(cms, cms_two);
	print count_min_sketch_estimate(new, 0);
	print count_min_sketch_estimate(new, 42);
	print count_min_sketch_estimate(new, 88);
	}

event zeek_init()
	{
	# hundred elements, 1% error allowable
	print count_min_sketch_calculate_required_width(0.001, .01);
	print count_min_sketch_calculate_required_depth(0.001, .01);
	# thousand elements, 1% error allowable
	print count_min_sketch_calculate_required_width(0.001, .001);
	print count_min_sketch_calculate_required_depth(0.001, .001);
	# a hundred thousand elements, 1% error allowable
	print count_min_sketch_calculate_required_width(0.001, .00001);
	print count_min_sketch_calculate_required_depth(0.001, .00001);
	# one million elements, 1% error allowable
	print count_min_sketch_calculate_required_width(0.001, .000001);
	print count_min_sketch_calculate_required_depth(0.001, .000001);
	# one million elements, 10% error allowable
	print count_min_sketch_calculate_required_width(0.01, .000001);
	print count_min_sketch_calculate_required_depth(0.01, .000001);
	# a hundred thousand elements, 10% error allowable
	print count_min_sketch_calculate_required_width(0.01, .00001);
	print count_min_sketch_calculate_required_depth(0.01, .00001);
	advanced_test();
	advanced_test_two();
	merge_test();
	}
