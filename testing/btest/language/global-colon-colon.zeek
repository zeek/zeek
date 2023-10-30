# @TEST-DOC: GLOBAL:: and just :: are the same, adapt with v7.1 to remove GLOBAL:: usage.
# @TEST-EXEC: zeek -b %INPUT >out

# @TEST-EXEC: btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

module GLOBAL;

global X = "global X";

global my_hook: hook();
global my_event: event();

function func() {
	print "  GLOBAL::func()";
}

module MyModule;

export {
	global X = "MyModule X";
	global my_hook: hook();
	global my_event: event();
	global func: function();
}

# This implements MyModule::my_hook()
hook my_hook() &priority=9
	{
	print "  MyModule::my_hook()";
	}

# This implements GLOBAL::my_hook()
hook ::my_hook() &priority=8
	{
	print "  ::my_hook() (in MyModule using ::)";
	}

event my_event() &priority=9
	{
	print "  MyModule::my_event() (in MyModule)";
	}

event ::my_event() &priority=8
	{
	print "  ::my_event() (in MyModule)";
	}

function func()
	{
	print "  MyModule::func()";
	}

# This one is a bit funky: Defines a global function while in a module.
function ::funcX()
	{
	print "  ::funcX() (in MyModule)";
	}

event zeek_init() &priority=5
	{
	print "(MyModule) print X";
	print fmt("  %s", X);
	print "(MyModule) print MyModule::X";
	print fmt("  %s", MyModule::X);
	print "(MyModule) print GLOBAL::X";
	print fmt("  %s", GLOBAL::X);
	print "(MyModule) print ::X";
	print fmt("  %s", ::X);
	print "(MyModule) hook my_hook()";
	hook my_hook();  # This uses MyModule::my_hook();
	print "(MyModule) hook MyModule::my_hook()";
	hook MyModule::my_hook();  # This uses MyModule::hook();
	print "(MyModule) hook GLOBAL::my_hook()";
	hook GLOBAL::my_hook();
	print "(MyModule) hook ::my_hook()";
	hook ::my_hook();

	print "(MyModule) call func()";
	func();
	print "(MyModule) call GLOBAL::func()";
	GLOBAL::func();
	print "(MyModule) call ::func()";
	::func();

	print "(MyModule) call funcX()";
	funcX();
	print "(MyModule) call GLOBAL::funcX()";
	GLOBAL::funcX();
	print "(MyModule) call ::funcX()";
	::funcX();

	# This schedules MyEvent::my_event()
	event my_event();

	# This schedules the GLOBAL::my_event();
	event ::my_event();
	}


module GLOBAL;

event zeek_init() &priority=5
	{
	print "(G) print X";
	print fmt("  %s", X);
	print "(G) print MyModule::X";
	print fmt("  %s", MyModule::X);
	print "(G) print GLOBAL::X";
	print fmt("  %s", GLOBAL::X);
	print "(G) print ::X";
	print fmt("  %s", ::X);
	print "(G) hook my_hook()";
	hook my_hook();  # This uses GLOBAL::my_hook();
	print "(G) MyModule::my_hook()";
	hook MyModule::my_hook();  # This uses MyModule::hook();
	print "(G) hook GLOBAL::my_hook()";
	hook GLOBAL::my_hook();
	print "(G) hook ::my_hook()";
	hook ::my_hook();

	print "(G) call func()";
	func();
	print "(G) call GLOBAL::func()";
	GLOBAL::func();
	print "(G) call ::func()";
	::func();

	print "(G) call funcX()";
	funcX();
	print "(G) call GLOBAL::funcX()";
	GLOBAL::funcX();
	print "(G) call ::funcX()";
	::funcX();
	}

hook my_hook() &priority=10
	{
	print "  my_hook() (in GLOBAL)";
	}

hook ::my_hook() &priority=10
	{
	print "  ::my_hook() (in GLOBAL)";
	}

hook MyModule::my_hook() &priority=10
	{
	print "  MyModule::my_hook() (in GLOBAL)";
	}

event MyModule::my_event() &priority=9
	{
	print "  MyModule::my_event() (in GLOBAL)";
	}

event my_event() &priority=10
	{
	print "  my_event() (in GLOBAL)";
	}

event ::my_event() &priority=10
	{
	print "  ::my_event() in (in GLOBAL)";
	}
