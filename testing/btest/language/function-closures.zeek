# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

global numberone : count = 1;

function make_count_upper (start : count) : function(step : count) : count
	{
	return function(step : count) : count
		{ return (start += (step + numberone)); };
        }

event zeek_init()
	{
	# basic
	local one = make_count_upper(1);
	print "expect: 4";
	print one(2);

	# multiple instances
	local two = make_count_upper(one(1));
	print "expect: 8";
	print two(1);
	print "expect: 8";
	print one(1);

	# deep copies
	local c = copy(one);
	print "expect: T";
	print c(1) == one(1);
	print "expect: T";
	print c(1) == two(3);
	
	# a little more complicated ...
	local cat_dog = 100;
	local add_n_and_m = function(n: count) : function(m : count) : function(o : count) : count
		{
		cat_dog += 1; # segfault here.
		return function(m : count) : function(o : count) : count
			{ return function(o : count) : count
				{ return  n + m + o + cat_dog; }; };
		};

	local add_m = add_n_and_m(2);
	local adder = add_m(2);
	
	print "expect: 107";	
	print adder(2);

	print "expect: 107";
	# deep copies
	local ac = copy(adder);
	print ac(2);

	# copies closure:
	print "expect: 100";
	print cat_dog;
	
	# complicated - has state across calls
	local two_part_adder_maker = function (begin : count) : function (base_step : count) : function ( step : count) : count
		{
		return function (base_step : count) : function (step : count) : count
			{
				return function (step : count) : count
					{
					return (begin += base_step + step); }; }; };
	
	local base_step = two_part_adder_maker(100);
	local stepper = base_step(50);
	print "expect: 160";
	print stepper(10);
	local twotwofive = copy(stepper);
	print "expect: 225";
	print stepper(15);

	# another copy check
	print "expect: 225";
	print twotwofive(15);
	}

