# @TEST-EXEC: mkdir fail.sqlite
# @TEST-EXEC: btest-bg-run zeek "BROKER_FILE_VERBOSITY=error BROKER_CONSOLE_VERBOSITY=quiet zeek -b %INPUT >out 2>err"
# @TEST-EXEC: btest-bg-wait 60
# @TEST-EXEC: btest-diff zeek/out
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-abspath $SCRIPTS/diff-sort" btest-diff zeek/err

redef exit_only_after_terminate = T;

global c = 0;
global m1: opaque of Broker::Store;
global m2: opaque of Broker::Store;
global c1: opaque of Broker::Store;
global c2: opaque of Broker::Store;

global check_it: function(name: string, s: opaque of Broker::Store);

function check_terminate_conditions()
	{
	++c;
	if ( c == 4 )
		{
		print Broker::is_closed(m1);
		print Broker::is_closed(m2);
		print Broker::is_closed(c1);
		print Broker::is_closed(c2);
		# Failed to originally open m1, so should raise an error.
		Broker::close(m1);
		Broker::close(m2);
		Broker::close(c1);
		# Closing c2 is an error since it's actually referring to m2, already
		# closed above (i.e. making a clone of a master store that already lives
		# in the same process, just returns a handle to the master).
		Broker::close(c2);
		print Broker::is_closed(m1);
		print Broker::is_closed(m2);
		print Broker::is_closed(c1);
		print Broker::is_closed(c2);
		check_it("m1", m1);
		check_it("c1", c1);
		check_it("m2", m2);
		check_it("c2", c2);
		}
	else if ( c == 8 )
		terminate();
	}

function check_it(name: string, s: opaque of Broker::Store)
	{
	when [name, s] ( local r = Broker::keys(s) )
		{
		check_terminate_conditions();
		print fmt("%s keys result: %s", name, r);
		}
	timeout 1sec
		{
		check_terminate_conditions();
		print fmt("%s timeout", name);
		}
	}

event zeek_init()
	{
	m1 = Broker::create_master("../fail", Broker::SQLITE);
	m2 = Broker::create_master("ok");
	c1 = Broker::create_clone("../fail");
	c2 = Broker::create_clone("ok");

	print Broker::is_closed(m1);
	print Broker::is_closed(m2);
	print Broker::is_closed(c1);
	print Broker::is_closed(c2);

	check_it("m1", m1);
	check_it("c1", c1);
	check_it("m2", m2);
	check_it("c2", c2);
	}
