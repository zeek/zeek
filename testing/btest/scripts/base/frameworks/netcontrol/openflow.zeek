# @TEST-EXEC: zeek -r $TRACES/smtp.trace %INPUT
# @TEST-EXEC: btest-diff netcontrol.log
# @TEST-EXEC: btest-diff openflow.log

@load base/frameworks/netcontrol

global of_controller: OpenFlow::Controller;

event NetControl::init()
	{
	of_controller = OpenFlow::log_new(42);
	local netcontrol_of = NetControl::create_openflow(of_controller);
	NetControl::activate(netcontrol_of, 0);
	}

event connection_established(c: connection)
	{
	local id = c$id;
	NetControl::shunt_flow([$src_h=id$orig_h, $src_p=id$orig_p, $dst_h=id$resp_h, $dst_p=id$resp_p], 30sec);
	NetControl::drop_address(id$resp_h, 15sec);
	}
