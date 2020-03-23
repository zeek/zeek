# @TEST-EXEC: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: btest-diff out

event zeek_script_loaded(path: string, level: count) &priority=10
	{
	if ( /zeek_script_loaded.zeek/ in path )
		print "zeek_script_loaded priority 10";
	}

event zeek_script_loaded(path: string, level: count) &priority=0
	{
	if ( /zeek_script_loaded.zeek/ in path )
		print "zeek_script_loaded priority 0";
	}
