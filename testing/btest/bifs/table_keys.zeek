#
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local t = table(
		["http"] = "http://www.google.com/",
		["https"] = "https://www.google.com/"
    );
	
	local v: set[string] = table_keys(t);

	print v;
	}