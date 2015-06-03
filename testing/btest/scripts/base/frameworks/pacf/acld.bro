# @TEST-SERIALIZE: brokercomm
# @TEST-REQUIRES: grep -q ENABLE_BROKER $BUILD/CMakeCache.txt
# @TEST-EXEC: btest-bg-run recv "bro -b ../recv.bro broker_port=$BROKER_PORT >recv.out"
# @TEST-EXEC: btest-bg-run send "bro -b -r $TRACES/smtp.trace --pseudo-realtime ../send.bro broker_port=$BROKER_PORT >send.out"

# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff recv/recv.out
# @TEST-EXEC: btest-diff send/send.out

@TEST-START-FILE send.bro

@load base/frameworks/pacf

const broker_port: port &redef;
redef exit_only_after_terminate = T;

event bro_init()
	{
	suspend_processing();
	local pacf_acld = Pacf::create_acld(Pacf::AcldConfig($acld_host=127.0.0.1, $acld_port=broker_port, $acld_topic="bro/event/pacftest"));
	Pacf::activate(pacf_acld, 0);
	}

event BrokerComm::outgoing_connection_established(peer_address: string,
                                            peer_port: port,
                                            peer_name: string)
	{
	print "BrokerComm::outgoing_connection_established", peer_address, peer_port;
	continue_processing();
	}

event BrokerComm::outgoing_connection_broken(peer_address: string,
                                       peer_port: port)
	{
	terminate();
	}

event connection_established(c: connection)
	{
	local id = c$id;

	local flow1 = Pacf::Flow(
		$src_h=addr_to_subnet(c$id$orig_h),
		$dst_h=addr_to_subnet(c$id$resp_h)
	);
	local e1: Pacf::Entity = [$ty=Pacf::FLOW, $flow=flow1];
	local r1: Pacf::Rule = [$ty=Pacf::DROP, $target=Pacf::FORWARD, $entity=e1, $expire=10hrs, $location="here"];

	local flow2 = Pacf::Flow(
		$dst_p=c$id$resp_p
	);
	local e2: Pacf::Entity = [$ty=Pacf::FLOW, $flow=flow2];
	local r2: Pacf::Rule = [$ty=Pacf::DROP, $target=Pacf::FORWARD, $entity=e2, $expire=10hrs, $location="here"];

	Pacf::add_rule(r1);
	Pacf::add_rule(r2);
	Pacf::drop_address(id$orig_h, 10hrs);
	}

event Pacf::rule_added(r: Pacf::Rule, p: Pacf::PluginState, msg: string)
	{
	print "rule added", r;
	Pacf::remove_rule(r$id);
	}

event Pacf::rule_removed(r: Pacf::Rule, p: Pacf::PluginState, msg: string)
	{
	print "rule removed", r;
	}

@TEST-END-FILE

@TEST-START-FILE recv.bro

@load base/frameworks/pacf
@load base/frameworks/broker

const broker_port: port &redef;
redef exit_only_after_terminate = T;

event bro_init()
	{
	BrokerComm::enable();
	BrokerComm::subscribe_to_events("bro/event/pacftest");
	BrokerComm::listen(broker_port, "127.0.0.1");
	}

event BrokerComm::incoming_connection_established(peer_name: string)
	{
	print "BrokerComm::incoming_connection_established";
	}

event Pacf::acld_add_rule(id: count, r: Pacf::Rule, ar: Pacf::AclRule)
	{
	print "add_rule", id, r, ar;

	BrokerComm::event("bro/event/pacftest", BrokerComm::event_args(Pacf::acld_rule_added, id, r, ar$command));
	}

event Pacf::acld_remove_rule(id: count, r: Pacf::Rule, ar: Pacf::AclRule)
	{
	print "remove_rule", id, r, ar;

	BrokerComm::event("bro/event/pacftest", BrokerComm::event_args(Pacf::acld_rule_removed, id, r, ar$command));

	if ( r$cid == 4 )
		terminate();
	}

@TEST-END-FILE

