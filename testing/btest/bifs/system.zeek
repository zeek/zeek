#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff out2

event zeek_init()
	{
	local a = system("echo thistest > out");
	if ( a != 0 )
		exit(1);

	# Command containing embedded double quotes
	local b = system("echo \"quoted test\" > out2");
	if ( b != 0 )
		exit(1);
	}
