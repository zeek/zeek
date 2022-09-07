# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

event zeek_init()
{
	local t1 = table(
		["web"] = { [80/tcp, "http"], [443/tcp, "https"] },
		["login"] = { [21/tcp, "ftp"], [23/tcp, "telnet"] });

	local t2 = table(
		["even"] = { [10] = "ten", [4] = "four" }, 
		["odd"] = { [11] = "eleven", [5] = "five" });

	local t3 = table(
		["numbers"] = { 
			["even"] = { [10] = "ten", [4] = "four" }, 
			["odd"] = { [11] = "eleven", [5] = "five" }});

	local t4 = table(
		[0] = {$a = "foo", $b = 1});
	
	local t5 = table(
		[0] = {$a = "foo", $b = 1},
		[1] = {$a = "bar"});

	local t6 = table(
		[0] = {
			[10/tcp] = { ["1"] = {$a = "foo", $b = 1}, ["2"] = {$a = "foo"} }});

	print type_name(t1);
	print type_name(t2);
	print type_name(t3);
	print type_name(t4);
	print type_name(t5);
	print type_name(t6);
	
	print t1;
	print t2;
	print t3;
	print t4;
	print t5;
	print t6;
}
