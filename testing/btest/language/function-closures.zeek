# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

global numberone : count = 1;

function make_count_upper (start : count) : function(step : count) : count
	{
	return function(step : count) : count
		{ return (start += (step + numberone)); };
        }

function dog_maker(name: string, weight: count) : function (action: string)
	{
	local eat = function (lbs: count) { print fmt("eat i weigh %s", lbs); };
	local bark = function (who: string) { print fmt("bark i am %s", who); };

	local dog = function (action: string)
		{
		switch action
			{
			case "bark":
				bark(name);
				break;
			case "eat":
				++weight;
				eat(weight);
				break;
			default:
				print "I have a new name";
				name = action;
				break;
			}
		};
	return dog;
	}

function make_lambda(start: count): function(): count
	{
	return function(): count
		{
		local dummy: string;
		return 0;
		};
	}

event zeek_init() &priority=10
	{
	# just checking use of unitialized locals "works" (doesn't crash)
	local one = make_lambda(1);
	local two = make_lambda(2);
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
		cat_dog += 1;
		local can_we_make_variables_inside = 11;
		return function(m : count) : function(o : count) : count
			{ return function(o : count) : count
				{ return  n + m + o + cat_dog + can_we_make_variables_inside; }; };
		};

	local add_m = add_n_and_m(2);
	local adder = add_m(2);
	
	print "expect: 118";	
	print adder(2);

	print "expect: 118";
	# deep copies
	local ac = copy(adder);
	print ac(2);

	# can mutate closure:
	print "expect: 101";
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
	print "expect: 290";
	print twotwofive(15);

	local hamster : count = 3;
	
	print "";
	print "tables:";
	print "";
	# tables!
	local modes: table[count] of string = {
	    [1] = "symmetric active",
	    [2] = "symmetric passive",
	    [3] = "client",
            } &default = function(i: count):string { return fmt("unknown-%d. outside-%d", i, hamster += 1); } &redef;

	# changing the value here will show in the function.
	hamster += hamster;
	
	print "expect: unknown-11. outside-7";
	print modes[11];
	local dogs = copy(modes);
	print "expect: unknown-11. outside-8";
	print modes[11];

	print "expect: client";
	print modes[3];
	
	print "expect: client";
	print dogs[3];
	# this is subtle -> copying is a deep copy so afer the copy
	print "expect: unknown-33. outside-8";
	print dogs[33];	

	print "";

	local hamster_also = 3;

	local modes_also = table(
            [1] = "symmetric active",
            [2] = "symmetric passive",
            [3] = "client"
	)&default = function(i: count):string { return fmt("unknown-%d. outside-%d", i, hamster_also += 1); } &redef;

        print "expect: unknown-11. outside-4";
        print modes_also[11];
        local dogs_also = copy(modes_also);
        print "expect: unknown-11. outside-5";
        print modes_also[11];

        print "expect: client";
        print modes_also[3];

        print "expect: client";
        print dogs_also[3];
        print "expect: unknown-33. outside-5";
        print dogs_also[33];

	print "";
	print "classes!";
	print "";

	local dog = dog_maker("thunder", 12);
	dog("bark");
	dog("eat");
	dog("eat");

	local other_dog = copy(dog);
	other_dog("twig");
	other_dog("bark");
	
	dog("bark");
	} # zeek_init

