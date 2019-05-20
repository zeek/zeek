# @TEST-EXEC: zeek -r $TRACES/tls/ecdhe.pcap %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER='grep -v ^# | $SCRIPTS/diff-remove-timestamps' btest-diff netcontrol.log
# @TEST-EXEC: btest-diff netcontrol_catch_release.log

@load base/frameworks/netcontrol

event NetControl::init()
	{
	local netcontrol_debug = NetControl::create_debug(T);
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

event NetControl::rule_added(r: NetControl::Rule, p: NetControl::PluginState, msg: string &default="")
	{
	if ( ++i == 6 )
		return;

	# delete directly, without notifying anything.
	NetControl::delete_rule(r$id, "testing");
	NetControl::catch_release_seen(subnet_to_addr(r$entity$ip));
	}

@TEST-START-NEXT

@load base/frameworks/netcontrol

event NetControl::init()
	{
	local netcontrol_debug = NetControl::create_debug(T);
	NetControl::activate(netcontrol_debug, 0);
	}

global i: count = 0;

event connection_established(c: connection)
	{
	local id = c$id;
	NetControl::drop_address(id$orig_h, 2min);
	NetControl::drop_address_catch_release(id$orig_h, "test drop");
	}

event NetControl::rule_added(r: NetControl::Rule, p: NetControl::PluginState, msg: string &default="")
	{
	if ( ++i == 3 )
		return;

	# delete directly, without notifying anything.
	NetControl::delete_rule(r$id);
	NetControl::catch_release_seen(subnet_to_addr(r$entity$ip));
	}

