event zeek_init()
	{
	# int is a signed number
	local x: int = +5;
	local y: int = -2;
	print fmt("result x - y: %d", x - y); # prints "result x - y: 7"

	# count is an unsigned number
	local a: count = 10;
	local b: count = 15;
	a += b; # Add b to a, store the result in a
	print fmt("a is: %d", a); # prints "a is: 25"

	# bool can be T (for true) or F (for false)
	local my_true: bool = T;
	local my_false: bool = F;
	print fmt("true and false? %s", my_true
	    && my_false); # prints "true and false? F"
	print fmt("true or false? %s", my_true
	    || my_false); # prints "true or false? T"

	# string is just some text enclosed in quotes
	local bad_word: string = "bad";
	local phrase: string = "this is bad.";
	print fmt("bad? %s", bad_word in phrase); # prints "bad? T"

	# pattern is a regular expression
	local good_words = /good|great|amazing/; # any of these words will match
	print fmt("good? %s", good_words in phrase); # prints "good? F"
	phrase = "this is good!";
	print fmt("good this time? %s", good_words in phrase); # prints "good this time? T"
	}
