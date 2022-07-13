#
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local t1: table[count] of string = table([5] = "test", [0] = "example");
	local t2 = table(
		["web"] = { [80/tcp, "http"], [443/tcp, "https"] },
		["login"] = { [21/tcp, "ftp"], [23/tcp, "telnet"] });
	
	local v1: vector of set[string] = table_values(t1);
	local v2: vector of set[port, string] = table_values(t2);

	print v1;
	print v2;
	}
