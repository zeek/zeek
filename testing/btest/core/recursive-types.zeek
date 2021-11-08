# @TEST-EXEC: zeek -b %INPUT

# global_ids() here contains some types that are recursive, in that
# arguments to functions contain chained references to the type that
# defines the function. This tests that we don't crash when
# attempting to call Describe() on those types in binary-mode.
event zeek_init()
	{
	local sh: string = "";
	local gi =  global_ids();
        for (myfunc in gi)
		{
		if(gi[myfunc]?$value)
			{
			if(strstr(myfunc,"lambda") > 0)
				{
				sh = sha256_hash(gi[myfunc]$value);
				print(sh);
				}
			}
		}
	}
