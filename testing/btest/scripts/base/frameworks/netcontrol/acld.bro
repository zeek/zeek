# @TEST-SERIALIZE: brokercomm
# @TEST-REQUIRES: grep -q ENABLE_BROKER $BUILD/CMakeCache.txt
# @TEST-EXEC: btest-bg-run recv "bro -b ../recv.bro broker_port=$BROKER_PORT >recv.out"
# @TEST-EXEC: btest-bg-run send "bro -b -r $TRACES/tls/ecdhe.pcap --pseudo-realtime ../send.bro broker_port=$BROKER_PORT >send.out"

# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff recv/recv.out
# @TEST-EXEC: btest-diff send/send.out

@TEST-START-FILE send.bro

@load base/frameworks/netcontrol

const broker_port: port &redef;
redef exit_only_after_terminate = T;

event bro_init()
	{
	suspend_processing();
	local netcontrol_acld = NetControl::create_acld(NetControl::AcldConfig($acld_host=127.0.0.1, $acld_port=broker_port, $acld_topic="bro/event/netcontroltest"));
	NetControl::activate(netcontrol_acld, 0);
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

	local flow1 = NetControl::Flow(
		$src_h=addr_to_subnet(c$id$orig_h),
		$dst_h=addr_to_subnet(c$id$resp_h)
	);
	local e1: NetControl::Entity = [$ty=NetControl::FLOW, $flow=flow1];
	local r1: NetControl::Rule = [$ty=NetControl::DROP, $target=NetControl::FORWARD, $entity=e1, $expire=10hrs, $location="here"];

	local flow2 = NetControl::Flow(
		$dst_p=c$id$resp_p
	);
	local e2: NetControl::Entity = [$ty=NetControl::FLOW, $flow=flow2];
	local r2: NetControl::Rule = [$ty=NetControl::DROP, $target=NetControl::FORWARD, $entity=e2, $expire=10hrs, $location="there"];

	NetControl::add_rule(r1);
	NetControl::add_rule(r2);
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

event NetControl::acld_add_rule(id: count, r: NetControl::Rule, ar: NetControl::AclRule)
	{
	print "add_rule", id, r, ar;

	BrokerComm::event("bro/event/netcontroltest", BrokerComm::event_args(NetControl::acld_rule_added, id, r, ar$command));
	}

event NetControl::acld_remove_rule(id: count, r: NetControl::Rule, ar: NetControl::AclRule)
	{
	print "remove_rule", id, r, ar;

	BrokerComm::event("bro/event/netcontroltest", BrokerComm::event_args(NetControl::acld_rule_removed, id, r, ar$command));

	if ( r$cid == 4 )
		terminate();
	}

@TEST-END-FILE

