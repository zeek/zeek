# @TEST-EXEC: zeek -b -r $TRACES/tls/ecdhe.pcap %INPUT
# @TEST-EXEC: btest-diff netcontrol.log

@load base/frameworks/netcontrol

event NetControl::init()
	{
	local netcontrol_debug = NetControl::create_debug(T, "plugin-1");
	local netcontrol_debug_exists = NetControl::create_debug_exists("plugin-2");
	NetControl::activate(netcontrol_debug, 0);
	NetControl::activate(netcontrol_debug_exists, 0);
	}

event connection_established(c: connection)
	{
	local id = c$id;
	NetControl::drop_address(id$orig_h, 1sec);
	}

@TEST-START-NEXT

@load base/frameworks/netcontrol

event NetControl::init()
	{
	local netcontrol_debug = NetControl::create_debug(T, "plugin-1");
	local netcontrol_debug_exists = NetControl::create_debug_exists("plugin-2");
	NetControl::activate(netcontrol_debug, 0);
	NetControl::activate(netcontrol_debug_exists, 0);
	}

event connection_established(c: connection)
	{
	local id = c$id;
	NetControl::drop_address(id$orig_h, 1sec);
	}

hook NetControl::rule_added_policy(r: NetControl::Rule, p: NetControl::PluginState, exists: bool, msg: string)
	{
	if ( exists )
		# force expiration, even if rule exists
		if ( p$_id in r$_no_expire_plugins )
			delete r$_no_expire_plugins[p$_id];
	}


