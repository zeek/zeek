# @TEST-EXEC: zeek -b -r $TRACES/tls/google-duplicate.trace %INPUT
# @TEST-EXEC: btest-diff netcontrol.log

@load base/frameworks/netcontrol

event NetControl::init()
	{
	local netcontrol_debug = NetControl::create_debug(T);
	NetControl::activate(netcontrol_debug, 0);
	}

event connection_established(c: connection)
	{
	NetControl::drop_address(c$id$orig_h, 0secs);
	}
