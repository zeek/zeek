# @TEST-SERIALIZE: brokercomm
# @TEST-REQUIRES: grep -q ENABLE_BROKER $BUILD/CMakeCache.txt
# @TEST-EXEC: btest-bg-run recv "bro -b ../recv.bro broker_port=$BROKER_PORT >recv.out"
# @TEST-EXEC: btest-bg-run send "bro -b -r $TRACES/smtp.trace --pseudo-realtime ../send.bro broker_port=$BROKER_PORT >send.out"

# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff recv/recv.out
# @TEST-EXEC: btest-diff send/send.out

@TEST-START-FILE send.bro

@load base/protocols/conn
@load base/frameworks/openflow

const broker_port: port &redef;
redef exit_only_after_terminate = T;

global of_controller: OpenFlow::Controller;

event bro_init()
	{
	suspend_processing();
	of_controller = OpenFlow::broker_new("broker1", 127.0.0.1, broker_port, "bro/event/openflow", 42);
	}

event BrokerComm::outgoing_connection_established(peer_address: string,
                                            peer_port: port,
                                            peer_name: string)
	{
	print "BrokerComm::outgoing_connection_established", peer_address, peer_port;
	continue_processing();
	OpenFlow::flow_clear(of_controller);
	OpenFlow::flow_mod(of_controller, [], [$cookie=1, $command=OpenFlow::OFPFC_ADD, $actions=[$out_ports=vector(3, 7)]]);
	}

event BrokerComm::outgoing_connection_broken(peer_address: string,
                                       peer_port: port)
	{
	terminate();
	}

event connection_established(c: connection)
	{
	print "connection established";
	local match = OpenFlow::match_conn(c$id);
	local match_rev = OpenFlow::match_conn(c$id, T);

	local flow_mod: OpenFlow::ofp_flow_mod = [
		$cookie=42,
		$command=OpenFlow::OFPFC_ADD,
		$idle_timeout=30,
		$priority=5
	];

	OpenFlow::flow_mod(of_controller, match, flow_mod);
	OpenFlow::flow_mod(of_controller, match_rev, flow_mod);
	}

event OpenFlow::flow_mod_success(match: OpenFlow::ofp_match, flow_mod: OpenFlow::ofp_flow_mod, msg: string)
	{
	print "Flow_mod_success";
	}

event OpenFlow::flow_mod_failure(match: OpenFlow::ofp_match, flow_mod: OpenFlow::ofp_flow_mod, msg: string)
	{
	print "Flow_mod_failure";
	}

@TEST-END-FILE

@TEST-START-FILE recv.bro

@load base/frameworks/openflow

const broker_port: port &redef;
redef exit_only_after_terminate = T;

global msg_count: count = 0;

event bro_init()
	{
	BrokerComm::enable();
	BrokerComm::subscribe_to_events("bro/event/openflow");
	BrokerComm::listen(broker_port, "127.0.0.1");
	}

event BrokerComm::incoming_connection_established(peer_name: string)
	{
	print "BrokerComm::incoming_connection_established";
	}

function got_message()
	{
	++msg_count;

	if ( msg_count >= 4 )
		terminate();
	}

event OpenFlow::broker_flow_mod(dpid: count, match: OpenFlow::ofp_match, flow_mod: OpenFlow::ofp_flow_mod)
	{
	print "got flow_mod", dpid, match, flow_mod;
	BrokerComm::event("bro/event/openflow", BrokerComm::event_args(OpenFlow::flow_mod_success, match, flow_mod, ""));
	BrokerComm::event("bro/event/openflow", BrokerComm::event_args(OpenFlow::flow_mod_failure, match, flow_mod, ""));
	got_message();
	}

event OpenFlow::broker_flow_clear(dpid: count)
	{
	print "flow_clear", dpid;
	got_message();
	}


@TEST-END-FILE

