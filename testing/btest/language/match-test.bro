# @TEST-EXEC: bro %INPUT  >output 2>&1
# @TEST-EXEC: btest-diff output

global match_stuff = {
	[$pred(a: count) = { return a > 5; },
	 $result = "it's big",
	 $priority = 2],

	[$pred(a: count) = { return a > 15; },
	 $result = "it's really big",
	 $priority = 3],

	[$pred(a: count) = { return T; },
	 $result = "default",
	 $priority = 0],
};

print match 0 using match_stuff;
print match 10 using match_stuff;
print match 20 using match_stuff;
