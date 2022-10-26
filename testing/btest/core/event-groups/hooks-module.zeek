# @TEST-DOC: Very basic testing that hooks in modules are disabled through disable_module_events(), too.
# @TEST-EXEC: zeek %INPUT > output
# @TEST-EXEC: btest-diff output

module HookModule;

export {
	global module_hook: hook(c: count);
}

module MyModule;

hook HookModule::module_hook(c: count)
	{
	print "HookModule::module_hook in MyModule", c;
	}

event zeek_done()
	{
	print "FAIL: zeek_done in MyModule";
	}

module MyOtherModule;

hook HookModule::module_hook(c: count)
	{
	print "HookModule::module_hook in MyOtherModule", c;
	}

event zeek_done()
	{
	print "zeek_done in MyOtherModule";
	}

module GLOBAL;

hook HookModule::module_hook(c: count)
	{
	print "HookModule::module_hook in GLOBAL", c;
	}

event zeek_init()
	{
	hook HookModule::module_hook(1);
	print "=== disable_module_events(MyModule)";
	disable_module_events("MyModule");
	hook HookModule::module_hook(2);
	}

event zeek_done()
	{
	print "zeek_done in global";
	}
