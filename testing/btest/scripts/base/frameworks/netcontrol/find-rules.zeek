# @TEST-EXEC: zeek %INPUT
# @TEST-EXEC: btest-diff out

@load base/frameworks/netcontrol

global outfile: file;

event NetControl::init()
	{
	local netcontrol_debug = NetControl::create_debug(T);
	NetControl::activate(netcontrol_debug, 0);
	}

event NetControl::init_done() &priority=-5
	{
	NetControl::shunt_flow([$src_h=192.168.17.1, $src_p=32/tcp, $dst_h=192.168.17.2, $dst_p=32/tcp], 30sec);
	NetControl::drop_address(1.1.2.2, 15sec, "Hi there");
	NetControl::whitelist_address(1.2.3.4, 15sec);
	NetControl::redirect_flow([$src_h=192.168.17.1, $src_p=32/tcp, $dst_h=192.168.17.2, $dst_p=32/tcp], 5, 30sec);
	NetControl::quarantine_host(127.0.0.2, 8.8.8.8, 127.0.0.3, 15sec);

	outfile = open("out");
	local rules = NetControl::find_rules_addr(1.2.3.4);
	print outfile, |rules|;
	print outfile, rules[0]$entity;
	rules = NetControl::find_rules_addr(1.2.3.5);
	print outfile, |rules|;
	rules = NetControl::find_rules_addr(127.0.0.2);
	print outfile, |rules|;
	print outfile, rules[0]$entity, rules[0]$ty;
	print outfile, rules[3]$entity, rules[3]$ty;
	close(outfile);
	}

