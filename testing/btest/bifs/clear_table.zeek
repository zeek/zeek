#
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local mytable: table[string] of string = { ["key1"] = "val1" };

	print |mytable|;

	clear_table(mytable);

	print |mytable|;
	}
