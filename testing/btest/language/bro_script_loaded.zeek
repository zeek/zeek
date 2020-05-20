# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

event bro_script_loaded(path: string, level: count) &priority=5
	{
	if ( /zeek_script_loaded.zeek/ in path )
		print "bro_script_loaded priority 5";
	}
