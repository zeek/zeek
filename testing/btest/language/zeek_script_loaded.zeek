# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

event zeek_script_loaded(path: string, level: count) &priority=10
	{
	if ( /zeek_script_loaded.zeek/ in path )
		print "zeek_script_loaded priority 10";
	}

event bro_script_loaded(path: string, level: count) &priority=5
	{
	if ( /zeek_script_loaded.zeek/ in path )
		print "bro_script_loaded priority 5";
	}

event zeek_script_loaded(path: string, level: count) &priority=0
	{
	if ( /zeek_script_loaded.zeek/ in path )
		print "zeek_script_loaded priority 0";
	}

event bro_script_loaded(path: string, level: count) &priority=-10
	{
	if ( /zeek_script_loaded.zeek/ in path )
		print "bro_script_loaded priority -10";
	}
