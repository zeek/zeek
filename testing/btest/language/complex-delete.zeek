# @TEST-EXEC: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

event zeek_init()
	{
	local my_var: table[string] of table[string] of vector of count;
	my_var["a"] = table(["1"]=vector(), ["2"]=vector());
	my_var["a"]["1"] += 16;

	# This used to crash.
	delete my_var["a"];

	print "I didn't crash!";
	}
