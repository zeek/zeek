#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff testfile

event zeek_init()
	{
	local vars: table[string] of string = { ["TESTBRO"] = "helloworld" };

	# make sure the env. variable is not set
	local myvar = getenv("BRO_ARG_TESTBRO");
	if ( |myvar| != 0 )
		exit(1);

	# check if command runs with the env. variable defined
	local a = system_env("echo $BRO_ARG_TESTBRO > testfile", vars);
	if ( a != 0 )
		exit(1);

	# make sure the env. variable is still not set
	myvar = getenv("BRO_ARG_TESTBRO");
	if ( |myvar| != 0 )
		exit(1);
	}
