# @TEST-EXEC: zeek -r $TRACES/tls/ecdhe.pcap %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER='grep -v ^# | $SCRIPTS/diff-sort' btest-diff netcontrol.log
# @TEST-EXEC: btest-diff openflow.log

@load base/frameworks/netcontrol

global rules: vector of string;

event NetControl::init()
	{
	local netcontrol_debug = NetControl::create_debug(T);
	local netcontrol_debug_2 = NetControl::create_debug(T);
	local of_controller = OpenFlow::log_new(42);
	local netcontrol_of = NetControl::create_openflow(of_controller);
	NetControl::activate(netcontrol_debug, 10);
	NetControl::activate(netcontrol_of, 10);
	NetControl::activate(netcontrol_debug_2, 0);
	}

event remove_all()
	{
	for ( i in rules )
		NetControl::remove_rule(rules[i]);
	}


event connection_established(c: connection)
	{
	local id = c$id;
	rules += NetControl::shunt_flow([$src_h=id$orig_h, $src_p=id$orig_p, $dst_h=id$resp_h, $dst_p=id$resp_p], 0secs);
	rules += NetControl::drop_address(id$orig_h, 0secs);
	rules += NetControl::whitelist_address(id$orig_h, 0secs);
	rules += NetControl::redirect_flow([$src_h=id$orig_h, $src_p=id$orig_p, $dst_h=id$resp_h, $dst_p=id$resp_p], 5, 0secs);

	schedule 1sec { remove_all() };
	}

