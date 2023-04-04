# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

global g = 0;

event zeek_init()
	{
	local orig1 = "hello";
	local orig2 = 3.5;
	local orig3 = F;

	# Should be okay since no local captures.
	when ( g > 0 )
		{
		print g;
		}

	# Should generate an error.
	when ( g > 0 )
		{
		print orig1;
		}

	# Same.
	when ( g > 0 || orig3 )
		{
		print g;
		}

	# Same.
	when ( g > 0 )
		{
		print g;
		}
	timeout 1 sec
		{
		print orig1;
		}

	# Should be okay.
	when [orig2] ( g > 0 && orig2 < 10.0 )
		{
		print g;
		}

	# Should be okay.
	when [orig1] ( g > 0 )
		{
		print orig1;
		}

	# Should be okay.
	when [orig1] ( g > 0 )
		{
		print g;
		}
	timeout 1 sec
		{
		print orig1;
		}

	# Mismatch: missing a local.
	when [orig1] ( g > 0 )
		{
		print orig1;
		}
	timeout 1 sec
		{
		print orig2;
		}

	# Mismatch: overspecifies a local.
	when [orig1, orig2, orig3] ( g > 0 )
		{
		print orig1;
		}
	timeout 1 sec
		{
		print orig2;
		}

	# Should generate a "no such identifier" error.
	when [l1] ( local l1 = network_time() )
		{
		print l1;
		}

	# As should this.
	when [l2] ( g > 0 )
		{
		local l2 = network_time();
		print l2;
		}
	}
