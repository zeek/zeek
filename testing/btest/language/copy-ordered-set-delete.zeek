# @TEST-DOC: Regression test for segfaults with &ordered sets when these are copied and elements removed.
#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local x: set[string] = set("HTTP") &ordered;
	local y = copy(x);

	delete y["HTTP"];

	x = copy(y);
	print "empty", cat(x);
	}

# @TEST-START-NEXT
event zeek_init()
	{
	local x: set[string] = set("HTTP") &ordered;
	local y = copy(x);

	delete y["HTTP"];

	print "empty", cat(y);
	}

# @TEST-START-NEXT
event zeek_init()
	{
	local x: set[string] = set("HTTP", "SSH", "SSL") &ordered;
	local y = copy(x);

	delete y["HTTP"];
	delete y["SSL"];

	print "SSH", cat(y);
	}
