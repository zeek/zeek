# @TEST-EXEC: bro -r $TRACES/smtp.trace %INPUT
# @TEST-EXEC: btest-diff conn.log

@load base/frameworks/pacf

event bro_init()
	{
	local pacf_packetfilter = Pacf::create_packetfilter();
	Pacf::activate(pacf_packetfilter, 0);
	}

event connection_established(c: connection)
	{
	local e = Pacf::Entity($ty=Pacf::ADDRESS, $ip=addr_to_subnet(c$id$orig_h));
	local r = Pacf::Rule($ty=Pacf::DROP, $target=Pacf::MONITOR, $entity=e, $expire=10min);

	Pacf::add_rule(r);
	}
