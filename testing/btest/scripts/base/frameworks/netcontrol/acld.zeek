# @TEST-PORT: BROKER_PORT
# @TEST-EXEC: btest-bg-run recv "zeek -b ../recv.zeek >recv.out"
# @TEST-EXEC: btest-bg-run send "zeek -b -r $TRACES/tls/ecdhe.pcap --pseudo-realtime ../send.zeek >send.out"

# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff send/netcontrol.log
# @TEST-EXEC: btest-diff recv/recv.out
# @TEST-EXEC: btest-diff send/send.out

@TEST-START-FILE send.zeek

@load base/frameworks/netcontrol

redef exit_only_after_terminate = T;
global have_peer = F;
global did_init = F;

event zeek_init()
	{
	suspend_processing();
	}

event NetControl::init()
	{
	local netcontrol_acld = NetControl::create_acld(NetControl::AcldConfig($acld_host=127.0.0.1, $acld_port=to_port(getenv("BROKER_PORT")), $acld_topic="bro/event/netcontroltest"));
	NetControl::activate(netcontrol_acld, 0);
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "Broker peer added", endpoint$network$address, endpoint$network$bound_port == to_port(getenv("BROKER_PORT"));
	have_peer = T;

	if ( did_init && have_peer )
		continue_processing();
	}

event NetControl::init_done()
	{
	did_init = T;

	if ( did_init && have_peer )
		continue_processing();
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
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
	print "rule added", r$entity, r$ty;
	NetControl::remove_rule(r$id);
	}

event NetControl::rule_exists(r: NetControl::Rule, p: NetControl::PluginState, msg: string)
	{
	print "rule exists", r$entity, r$ty;
	NetControl::remove_rule(r$id);
	}

event NetControl::rule_removed(r: NetControl::Rule, p: NetControl::PluginState, msg: string)
	{
	print "rule removed", r$entity, r$ty;
	}

event NetControl::rule_error(r: NetControl::Rule, p: NetControl::PluginState, msg: string)
	{
	print "rule error", r$entity, r$ty;
	}

@TEST-END-FILE

@TEST-START-FILE recv.zeek

@load base/frameworks/netcontrol
@load base/frameworks/broker

redef exit_only_after_terminate = T;

event die()
	{
	terminate();
	}

event zeek_init()
	{
	Broker::subscribe("bro/event/netcontroltest");
	Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "Broker peer added";
	}

event NetControl::acld_add_rule(id: count, r: NetControl::Rule, ar: NetControl::AclRule)
	{
	print "add_rule", id, r$entity, r$ty, ar;

	if ( r$cid != 3 )
		Broker::publish("bro/event/netcontroltest", NetControl::acld_rule_added, id, r, ar$command);
	else
		Broker::publish("bro/event/netcontroltest", NetControl::acld_rule_exists, id, r, ar$command);
	}

event NetControl::acld_remove_rule(id: count, r: NetControl::Rule, ar: NetControl::AclRule)
	{
	print "remove_rule", id, r$entity, r$ty, ar;

	if ( r$cid != 2 )
		Broker::publish("bro/event/netcontroltest", NetControl::acld_rule_removed, id, r, ar$command);
	else
		Broker::publish("bro/event/netcontroltest", NetControl::acld_rule_error, id, r, ar$command);

	if ( r$cid == 4 )
		{
		schedule 2sec { die() };
		}
	}

@TEST-END-FILE

