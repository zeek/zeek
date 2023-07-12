# @TEST-DOC: Shadow zeek_init() event, demonstrate ::zeek_init() usage.
#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

module MyModule;

export {
	## MyModule::zeek_init() shadows global zeek_init() event.
	global zeek_init: event();
}

# This is never invoked!
event zeek_init()
	{
	print "MyModule::zeek_init() - FAIL";
	}

event ::zeek_init()
	{
	print "::zeek_init()";
	}
