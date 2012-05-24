#
# @TEST-EXEC: bro %INPUT
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local vars: table[string] of string = { ["TESTBRO"] = "helloworld" };

	# make sure the env. variable is not set
	local myvar = getenv("TESTBRO");
	if ( |myvar| != 0 )
		exit(1);

	local a = system_env("echo $TESTBRO > out", vars);
	if ( a != 0 )
		exit(1);

	myvar = getenv("TESTBRO");
	if ( |myvar| != 0 )
		exit(1);
	}
