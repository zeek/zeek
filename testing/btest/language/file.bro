# @TEST-EXEC: bro %INPUT
# @TEST-EXEC: btest-diff out1
# @TEST-EXEC: btest-diff out2


event bro_init()
{
	# Test using "print" statement to output directly to a file
	local f1: file = open( "out1" );
	print f1, 20;
	print f1, 12;
	close(f1);

	# Test again, but without explicitly using the type name in declaration
	local f2 = open( "out2" );
	print f2, "test", 123, 456;
	close(f2);
}

