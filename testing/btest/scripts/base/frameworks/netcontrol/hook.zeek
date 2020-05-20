# @TEST-EXEC: zeek -r $TRACES/tls/ecdhe.pcap %INPUT
# @TEST-EXEC: btest-diff netcontrol.log

@load base/frameworks/netcontrol

event NetControl::init()
	{
	local netcontrol_debug = NetControl::create_debug(T);
	NetControl::activate(netcontrol_debug, 0);
	}

event connection_established(c: connection)
	{
	local id = c$id;
	NetControl::shunt_flow([$src_h=id$orig_h, $src_p=id$orig_p, $dst_h=id$resp_h, $dst_p=id$resp_p], 30sec);
	NetControl::drop_address(id$orig_h, 15sec);
	NetControl::whitelist_address(id$orig_h, 15sec);
	NetControl::redirect_flow([$src_h=id$orig_h, $src_p=id$orig_p, $dst_h=id$resp_h, $dst_p=id$resp_p], 5, 30sec);
	}

hook NetControl::rule_policy(r: NetControl::Rule)
	{
	if ( r$expire == 15sec )
		break;

	r$entity$flow$src_h = 0.0.0.0/0;
	}
