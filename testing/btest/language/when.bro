# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out


event bro_init()
{
	local h1: addr = 127.0.0.1;

	when ( local h1name = lookup_addr(h1) )
		{ 
		print "lookup successful";
		}
	print "done";
}

