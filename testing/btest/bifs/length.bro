#
# @TEST-EXEC: bro %INPUT > out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local mytable: table[string] of string = { ["key1"] = "val1" };
	local myset: set[count] = set( 3, 6, 2, 7 );
	local myvec: vector of string = vector( "value1", "value2" );

	print length(mytable);
	print length(myset);
	print length(myvec);

	mytable = table();
	myset = set();
	myvec = vector();

	print length(mytable);
	print length(myset);
	print length(myvec);
	}
