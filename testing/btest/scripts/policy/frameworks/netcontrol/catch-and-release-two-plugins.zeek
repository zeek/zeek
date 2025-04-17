# @TEST-EXEC: zeek -b -r $TRACES/tls/ecdhe.pcap %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER='grep -v ^# | $SCRIPTS/diff-remove-timestamps' btest-diff netcontrol.log
# @TEST-EXEC: btest-diff netcontrol_catch_release.log

@load base/frameworks/netcontrol
@load policy/frameworks/netcontrol/catch-and-release

event NetControl::init()
	{
	local netcontrol_debug = NetControl::create_debug(T, "plugin-1");
	local netcontrol_debug_two = NetControl::create_debug(T, "plugin-2");
	NetControl::activate(netcontrol_debug, 0);
	NetControl::activate(netcontrol_debug_two, 0);
	}

global i: count = 0;

event connection_established(c: connection)
	{
	local id = c$id;
	NetControl::drop_address_catch_release(id$orig_h);
	# second one should be ignored because duplicate
	NetControl::drop_address_catch_release(id$orig_h);
	}

event NetControl::rule_added(r: NetControl::Rule, p: NetControl::PluginState, msg: string)
	{
	if ( p$plugin$name(p) == "plugin-1" )
		return;

	if ( ++i >= 6 )
		return;

	# delete directly, without notifying anything.
	NetControl::delete_rule(r$id, "testing");
	NetControl::catch_release_seen(subnet_to_addr(r$entity$ip));
	}


# @TEST-START-NEXT

@load base/frameworks/netcontrol
@load policy/frameworks/netcontrol/catch-and-release

event NetControl::init()
	{
	local netcontrol_debug = NetControl::create_debug(T, "plugin-1");
	local netcontrol_debug_two = NetControl::create_debug_exists("exists");
	local netcontrol_debug_error = NetControl::create_debug_error("error");
	NetControl::activate(netcontrol_debug_two, 0);
	NetControl::activate(netcontrol_debug_error, 0);
	NetControl::activate(netcontrol_debug, 0);
	}

global i: count = 0;

event connection_established(c: connection)
	{
	local id = c$id;
	NetControl::drop_address_catch_release(id$orig_h);
	# second one should be ignored because duplicate
	NetControl::drop_address_catch_release(id$orig_h);
	}

event NetControl::rule_added(r: NetControl::Rule, p: NetControl::PluginState, msg: string)
	{
	if ( p$plugin$name(p) != "plugin-1" )
		return;

	if ( ++i >= 6 )
		return;

	# delete directly, without notifying anything.
	NetControl::delete_rule(r$id, "testing");
	NetControl::catch_release_seen(subnet_to_addr(r$entity$ip));
	}

