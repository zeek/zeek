# @TEST-SERIALIZE: brokercomm
# @TEST-REQUIRES: grep -q ENABLE_BROKER $BUILD/CMakeCache.txt
# @TEST-EXEC: btest-bg-run recv "bro -b ../recv.bro broker_port=$BROKER_PORT >recv.out"
# @TEST-EXEC: btest-bg-run send "bro -b -r $TRACES/smtp.trace --pseudo-realtime ../send.bro broker_port=$BROKER_PORT >send.out"

# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff send/netcontrol.log
# @TEST-EXEC: btest-diff recv/recv.out
# @TEST-EXEC: btest-diff send/send.out

@TEST-START-FILE send.bro

@load base/frameworks/netcontrol

const broker_port: port &redef;
redef exit_only_after_terminate = T;

event bro_init()
	{
	suspend_processing();
	local netcontrol_broker = NetControl::create_broker(127.0.0.1, broker_port, "bro/event/netcontroltest", T);
	NetControl::activate(netcontrol_broker, 0);
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
	NetControl::shunt_flow([$src_h=id$orig_h, $src_p=id$orig_p, $dst_h=id$resp_h, $dst_p=id$resp_p], 10hrs);
	NetControl::drop_address(id$orig_h, 10hrs);
	}

event NetControl::rule_added(r: NetControl::Rule, p: NetControl::PluginState, msg: string)
	{
	print "rule added", r;
	NetControl::remove_rule(r$id);
	}

event NetControl::rule_removed(r: NetControl::Rule, p: NetControl::PluginState, msg: string)
	{
	print "rule removed", r;
	}

event NetControl::rule_timeout(r: NetControl::Rule, i: NetControl::FlowInfo, p: NetControl::PluginState)
	{
	print "rule timeout", r, i;
	}

@TEST-END-FILE

@TEST-START-FILE recv.bro

@load base/frameworks/netcontrol
@load base/frameworks/broker

const broker_port: port &redef;
redef exit_only_after_terminate = T;

event bro_init()
	{
	BrokerComm::enable();
	BrokerComm::subscribe_to_events("bro/event/netcontroltest");
	BrokerComm::listen(broker_port, "127.0.0.1");
	}

event BrokerComm::incoming_connection_established(peer_name: string)
	{
	print "BrokerComm::incoming_connection_established";
	}

event NetControl::broker_add_rule(id: count, r: NetControl::Rule)
	{
	print "add_rule", id, r;

	BrokerComm::event("bro/event/netcontroltest", BrokerComm::event_args(NetControl::broker_rule_added, id, r, ""));
	}

event NetControl::broker_remove_rule(id: count, r: NetControl::Rule)
	{
	print "remove_rule", id, r;

	BrokerComm::event("bro/event/netcontroltest", BrokerComm::event_args(NetControl::broker_rule_timeout, id, r, NetControl::FlowInfo()));
	BrokerComm::event("bro/event/netcontroltest", BrokerComm::event_args(NetControl::broker_rule_removed, id, r, ""));

	if ( r$cid == 3 )
		terminate();
	}

@TEST-END-FILE

