# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff out1
# @TEST-EXEC: btest-diff out2


event zeek_init()
{
	local f1: file = open( "out1" );
	print f1, 20;
	print f1, 12;
	close(f1);

	# Type inference test

	local f2 = open( "out2" );
	print f2, "test", 123, 456;
	close(f2);
}

