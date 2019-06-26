#
# @TEST-EXEC: zeek -b %INPUT

event zeek_init()
	{
	local a = T;
	local b = 12;
	local c: table[string] of addr = { ["a"] = 192.168.0.2, ["b"] = 10.0.0.2 };

	if ( val_size(a) > val_size(b) )
		exit(1);

	if ( val_size(b) > val_size(c) )
		exit(1);

	}
