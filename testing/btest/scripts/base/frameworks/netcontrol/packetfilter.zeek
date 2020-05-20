# @TEST-EXEC: zeek -r $TRACES/smtp.trace %INPUT
# @TEST-EXEC: btest-diff conn.log

@load base/frameworks/netcontrol

event NetControl::init()
	{
	local netcontrol_packetfilter = NetControl::create_packetfilter();
	NetControl::activate(netcontrol_packetfilter, 0);
	}

event connection_established(c: connection)
	{
	local e = NetControl::Entity($ty=NetControl::ADDRESS, $ip=addr_to_subnet(c$id$orig_h));
	local r = NetControl::Rule($ty=NetControl::DROP, $target=NetControl::MONITOR, $entity=e, $expire=10min);

	NetControl::add_rule(r);
	}
