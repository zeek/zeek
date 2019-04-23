# @TEST-EXEC: zeek %INPUT
# @TEST-EXEC: btest-diff netcontrol.log
# @TEST-EXEC: btest-diff netcontrol_shunt.log
# @TEST-EXEC: btest-diff netcontrol_drop.log
# @TEST-EXEC: btest-diff .stdout

@load base/frameworks/netcontrol

event NetControl::init()
	{
	local netcontrol_debug = NetControl::create_debug(T);
	NetControl::activate(netcontrol_debug, 0);
	}

function test_mac_flow()
	{
	local flow = NetControl::Flow(
		$src_m = "FF:FF:FF:FF:FF:FF"
	);
	local e: NetControl::Entity = [$ty=NetControl::FLOW, $flow=flow];
	local r: NetControl::Rule = [$ty=NetControl::DROP, $target=NetControl::FORWARD, $entity=e, $expire=15sec];

	NetControl::add_rule(r);
	}

function test_mac()
	{
	local e: NetControl::Entity = [$ty=NetControl::MAC, $mac="FF:FF:FF:FF:FF:FF"];
	local r: NetControl::Rule = [$ty=NetControl::DROP, $target=NetControl::FORWARD, $entity=e, $expire=15sec];

	NetControl::add_rule(r);
	}

event NetControl::init_done() &priority=-5
	{
	NetControl::shunt_flow([$src_h=192.168.17.1, $src_p=32/tcp, $dst_h=192.168.17.2, $dst_p=32/tcp], 30sec);
	NetControl::drop_address(1.1.2.2, 15sec, "Hi there");
	NetControl::whitelist_address(1.2.3.4, 15sec);
	NetControl::redirect_flow([$src_h=192.168.17.1, $src_p=32/tcp, $dst_h=192.168.17.2, $dst_p=32/tcp], 5, 30sec);
	NetControl::quarantine_host(127.0.0.2, 8.8.8.8, 127.0.0.3, 15sec);
	test_mac();
	test_mac_flow();
	}

