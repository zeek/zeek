function our_openflow_check(p: NetControl::PluginState, r: NetControl::Rule): bool
	{
	if ( r$ty == NetControl::DROP &&
		r$entity$ty == NetControl::ADDRESS &&
		subnet_width(r$entity$ip) == 32 &&
		subnet_to_addr(r$entity$ip) in 192.168.17.0/24 )
		return F;

	return T;
	}

event NetControl::init()
	{
	# Add debug plugin with low priority
	local debug_plugin = NetControl::create_debug(T);
	NetControl::activate(debug_plugin, 0);

	# Instantiate OpenFlow debug plugin with higher priority
	local of_controller = OpenFlow::log_new(42);
	local netcontrol_of = NetControl::create_openflow(of_controller, [$check_pred=our_openflow_check]);
	NetControl::activate(netcontrol_of, 10);
	}

event NetControl::init_done()
	{
	NetControl::drop_address(10.0.0.1, 1min);
	NetControl::drop_address(192.168.17.2, 1min);
	NetControl::drop_address(192.168.18.2, 1min);
	}
