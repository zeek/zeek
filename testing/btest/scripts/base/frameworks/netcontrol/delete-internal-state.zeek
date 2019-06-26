# @TEST-EXEC: zeek -r $TRACES/tls/ecdhe.pcap %INPUT
# @TEST-EXEC: btest-diff .stdout

# Verify the state of internal tables after rules have been deleted...

@load base/frameworks/netcontrol

module NetControl;

export {
	global dump_state: function();
}

function dump_state()
	{
	print "Dumping state";
	print rules;
	print rule_entities;
	print rules_by_subnets;
	}

module GLOBAL;

global rules: vector of string;

event NetControl::init()
	{
	local netcontrol_debug = NetControl::create_debug(T);
	NetControl::activate(netcontrol_debug, 10);
	}

event remove_all()
	{
	for ( i in rules )
		NetControl::remove_rule(rules[i]);
	}

event dump_info()
	{
	NetControl::dump_state();
	}

event connection_established(c: connection)
	{
	local id = c$id;
	rules += NetControl::shunt_flow([$src_h=id$orig_h, $src_p=id$orig_p, $dst_h=id$resp_h, $dst_p=id$resp_p], 0secs);
	rules += NetControl::drop_address(id$orig_h, 0secs);
	rules += NetControl::whitelist_address(id$orig_h, 0secs);
	rules += NetControl::redirect_flow([$src_h=id$orig_h, $src_p=id$orig_p, $dst_h=id$resp_h, $dst_p=id$resp_p], 5, 0secs);

	schedule 1sec { remove_all() };
	schedule 2sec { dump_info() };
	}

