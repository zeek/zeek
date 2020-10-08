# @TEST-EXEC: zeek -b -- %INPUT -a -b -c 

# @TEST-EXEC: btest-diff .stdout

event zeek_init()
	{
	print zeek_script_args;
	}

