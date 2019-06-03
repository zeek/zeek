# @TEST-EXEC: zeek -r $TRACES/smtp.trace %INPUT
# @TEST-EXEC: btest-diff openflow.log

@load base/protocols/conn
@load base/frameworks/openflow

global of_controller: OpenFlow::Controller;

global cookie_id: count = 42;

event zeek_init()
	{
	of_controller = OpenFlow::log_new(42);

	OpenFlow::flow_mod(of_controller, [], [$cookie=OpenFlow::generate_cookie(1), $command=OpenFlow::OFPFC_ADD, $actions=[$out_ports=vector(3, 7)]]);
	}

event connection_established(c: connection)
	{
	local match = OpenFlow::match_conn(c$id);
	local match_rev = OpenFlow::match_conn(c$id, T);

	local flow_mod: OpenFlow::ofp_flow_mod = [
		$cookie=OpenFlow::generate_cookie(++cookie_id),
		$command=OpenFlow::OFPFC_ADD,
		$idle_timeout=30,
		$priority=5
	];

	OpenFlow::flow_mod(of_controller, match, flow_mod);
	OpenFlow::flow_mod(of_controller, match_rev, flow_mod);
	}
