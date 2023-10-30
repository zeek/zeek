# @TEST-DOC: global_ids() also includes information about modules
#
# @TEST-EXEC: unset ZEEK_ALLOW_INIT_ERRORS; zeek -b %INPUT >out 2>&1
# @TEST-EXEC: btest-diff out

module MyModule;

module GLOBAL;

# This shadows the module
global MyModule = "shadows module";

event zeek_init()
	{
	local a = global_ids();

	# Assert based testing.
	assert "module GLOBAL" in a;
	assert a["module GLOBAL"]$type_name == "module";

	assert "module MyModule" in a;
	assert a["module MyModule"]$type_name == "module";

	assert "MyModule" in a;
	assert a["MyModule"]$type_name == "string";

	# And a classic baseline test for now, too.
	for ( [k], v in a )
		{
		if ( k in set("module GLOBAL", "module MyModule", "MyModule") )
			print k, v;
		}
	}
