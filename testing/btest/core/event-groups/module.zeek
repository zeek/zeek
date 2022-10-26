# @TEST-DOC: Very basic testing of event groups for modules. The MyModule event group is disabled.
# @TEST-EXEC: zeek %INPUT > output
# @TEST-EXEC: btest-diff output

module MyModule;

event zeek_done()
	{
	print "FAIL: zeek_done within MyModule";
	}

module My::Nested::Module;

event zeek_done()
	{
	print "FAIL: zeek_done within My::Nested::Module";
	}

module MyOtherModule;

event zeek_done()
	{
	print "zeek_done within MyOtherModule";
	}

event zeek_done() &group="MyModule"
	{
	# continues to run because &group="MyModule" isn't the same
	# as the "MyModule" module group.
	print "zeek_done within MyOtherModule (&group=MyModule)";
	}

module GLOBAL;

event zeek_init()
	{
	print "zeek_init";

	disable_module_events("MyModule");
	disable_module_events("My::Nested::Module");
	}

# Re-open the MyModule module here once more.
module MyModule;

event zeek_done()
	{
	print "FAIL: Another zeek_done() within MyModule";
	}
