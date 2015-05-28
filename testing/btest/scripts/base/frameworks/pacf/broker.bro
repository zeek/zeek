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
	local pacf_broker = Pacf::create_broker(127.0.0.1, broker_port, "bro/event/pacftest", T);
	Pacf::activate(pacf_broker, 0);
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
	Pacf::shunt_flow([$src_h=id$orig_h, $src_p=id$orig_p, $dst_h=id$resp_h, $dst_p=id$resp_p], 10hrs);
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

event Pacf::rule_timeout(r: Pacf::Rule, i: Pacf::FlowInfo, p: Pacf::PluginState)
	{
	print "rule timeout", r, i;
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

event Pacf::broker_add_rule(id: count, r: Pacf::Rule)
	{
	print "add_rule", id, r;

	BrokerComm::event("bro/event/pacftest", BrokerComm::event_args(Pacf::broker_rule_added, id, r, ""));
	}

event Pacf::broker_remove_rule(id: count, r: Pacf::Rule)
	{
	print "remove_rule", id, r;

	BrokerComm::event("bro/event/pacftest", BrokerComm::event_args(Pacf::broker_rule_timeout, id, r, Pacf::FlowInfo()));
	BrokerComm::event("bro/event/pacftest", BrokerComm::event_args(Pacf::broker_rule_removed, id, r, ""));

	if ( r$cid == 3 )
		terminate();
	}

@TEST-END-FILE

