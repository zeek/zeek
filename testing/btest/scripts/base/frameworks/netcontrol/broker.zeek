# @TEST-PORT: BROKER_PORT
# @TEST-EXEC: btest-bg-run recv "zeek -b ../recv.zeek >recv.out"
# @TEST-EXEC: btest-bg-run send "zeek -b -r $TRACES/smtp.trace --pseudo-realtime ../send.zeek >send.out"

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
	local netcontrol_broker = NetControl::create_broker(NetControl::BrokerConfig($host=127.0.0.1, $bport=to_port(getenv("BROKER_PORT")), $topic="bro/event/netcontroltest"), T);
	NetControl::activate(netcontrol_broker, 0);
	}

event NetControl::init_done()
	{
	did_init = T;

	if ( did_init && have_peer )
		continue_processing();
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "Broker peer added", endpoint$network$address, endpoint$network$bound_port == to_port(getenv("BROKER_PORT"));
	have_peer = T;

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
	NetControl::shunt_flow([$src_h=id$orig_h, $src_p=id$orig_p, $dst_h=id$resp_h, $dst_p=id$resp_p], 10hrs);
	NetControl::drop_address(id$orig_h, 10hrs);
	}

event NetControl::rule_added(r: NetControl::Rule, p: NetControl::PluginState, msg: string)
	{
	print "rule added", r$entity, r$ty;
	NetControl::remove_rule(r$id, "removing");
	}

event NetControl::rule_exists(r: NetControl::Rule, p: NetControl::PluginState, msg: string)
	{
	print "rule exists", r$entity, r$ty;
	}

event NetControl::rule_removed(r: NetControl::Rule, p: NetControl::PluginState, msg: string)
	{
	print "rule removed", r$entity, r$ty;
	}

event NetControl::rule_timeout(r: NetControl::Rule, i: NetControl::FlowInfo, p: NetControl::PluginState)
	{
	print "rule timeout", r$entity, r$ty, i;
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

event NetControl::broker_add_rule(id: count, r: NetControl::Rule)
	{
	print "add_rule", id, r$entity, r$ty;

	if ( r$cid == 3 )
		Broker::publish("bro/event/netcontroltest", NetControl::broker_rule_added, id, r, "");
	if ( r$cid == 2 )
		Broker::publish("bro/event/netcontroltest", NetControl::broker_rule_exists, id, r, "");

	if ( r$cid == 2 )
		Broker::publish("bro/event/netcontroltest", NetControl::broker_rule_timeout, id, r, NetControl::FlowInfo());
	}

event NetControl::broker_remove_rule(id: count, r: NetControl::Rule, reason: string)
	{
	print "remove_rule", id, r$entity, r$ty, reason;

	Broker::publish("bro/event/netcontroltest", NetControl::broker_rule_removed, id, r, "");

	if ( r$cid == 3 )
		{
		schedule 2sec { die() };
		}
	}

@TEST-END-FILE

