# @TEST-PORT: BROKER_PORT
# @TEST-EXEC: btest-bg-run recv "zeek -b ../recv.zeek >recv.out"
# @TEST-EXEC: btest-bg-run send "zeek -b -r $TRACES/smtp.trace --pseudo-realtime ../send.zeek >send.out"

# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff recv/recv.out
# @TEST-EXEC: btest-diff send/send.out

@TEST-START-FILE send.zeek

@load base/protocols/conn
@load base/frameworks/openflow

redef exit_only_after_terminate = T;

global of_controller: OpenFlow::Controller;

event zeek_init()
	{
	suspend_processing();
	of_controller = OpenFlow::broker_new("broker1", 127.0.0.1, to_port(getenv("BROKER_PORT")), "bro/openflow", 42);
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "Broker peer added", endpoint$network$address, endpoint$network$bound_port == to_port(getenv("BROKER_PORT"));
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

event OpenFlow::controller_activated(name: string, controller: OpenFlow::Controller)
	{
	continue_processing();
	OpenFlow::flow_clear(of_controller);
	OpenFlow::flow_mod(of_controller, [], [$cookie=OpenFlow::generate_cookie(1), $command=OpenFlow::OFPFC_ADD, $actions=[$out_ports=vector(3, 7)]]);
	}

event connection_established(c: connection)
	{
	print "connection established";
	local match = OpenFlow::match_conn(c$id);
	local match_rev = OpenFlow::match_conn(c$id, T);

	local flow_mod: OpenFlow::ofp_flow_mod = [
		$cookie=OpenFlow::generate_cookie(42),
		$command=OpenFlow::OFPFC_ADD,
		$idle_timeout=30,
		$priority=5
	];

	OpenFlow::flow_mod(of_controller, match, flow_mod);
	OpenFlow::flow_mod(of_controller, match_rev, flow_mod);
	}

event OpenFlow::flow_mod_success(name: string, match: OpenFlow::ofp_match, flow_mod: OpenFlow::ofp_flow_mod, msg: string)
	{
	print "Flow_mod_success";
	}

event OpenFlow::flow_mod_failure(name: string, match: OpenFlow::ofp_match, flow_mod: OpenFlow::ofp_flow_mod, msg: string)
	{
	print "Flow_mod_failure";
	}

@TEST-END-FILE

@TEST-START-FILE recv.zeek

@load base/frameworks/openflow

redef exit_only_after_terminate = T;

global msg_count: count = 0;

event die()
	{
	terminate();
	}

event zeek_init()
	{
	Broker::subscribe("bro/openflow");
	Broker::listen("127.0.0.1", to_port(getenv("BROKER_PORT")));
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	print "Broker peer added";
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	terminate();
	}

function got_message()
	{
	++msg_count;

	if ( msg_count >= 4 )
		{
		schedule 2sec { die() };
		}
	}

event OpenFlow::broker_flow_mod(name: string, dpid: count, match: OpenFlow::ofp_match, flow_mod: OpenFlow::ofp_flow_mod)
	{
	print "got flow_mod", dpid, match, flow_mod;
	Broker::publish("bro/openflow", OpenFlow::flow_mod_success, name, match, flow_mod, "");
	Broker::publish("bro/openflow", OpenFlow::flow_mod_failure, name, match, flow_mod, "");
	got_message();
	}

event OpenFlow::broker_flow_clear(name: string, dpid: count)
	{
	print "flow_clear", dpid;
	got_message();
	}

@TEST-END-FILE

