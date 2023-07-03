# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER='$SCRIPTS/diff-remove-abspath' btest-diff .stderr


module MyModule;

module TestModule;

module GLOBAL;

# This shadows the TestModule.
global TestModule = "this shadows";

event zeek_init()
	{
	# Using a module in an expression.
	print "MyModule", type_name(MyModule), MyModule, fmt("fmt: %s", MyModule);
	print "TestModule", type_name(TestModule), TestModule;

	print "=== global_ids()";

	for ( [k], v in global_ids() )
		{
		if ( k == "Log::ID" || k == "MyModule" || k == "TestModule" )
			print k, v;
		}

	print "=== module_ids()";

	for ( [k], v in module_ids() )
		{
		if ( k == "Log::ID" || k == "MyModule" || k == "TestModule" )
			print k, v;
		}
	}
