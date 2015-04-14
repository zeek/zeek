# @TEST-EXEC: bro -r $TRACES/smtp.trace %INPUT
# @TEST-EXEC: btest-diff pacf.log
# @TEST-EXEC: btest-diff openflow.log

@load base/frameworks/pacf

global of_controller: OpenFlow::Controller;

event bro_init()
	{
	of_controller = OpenFlow::log_new(42);
	local pacf_of = Pacf::create_openflow(of_controller);
	Pacf::activate(pacf_of, 0);
	}

event connection_established(c: connection)
	{
	local id = c$id;
	Pacf::shunt_flow([$src_h=id$orig_h, $src_p=id$orig_p, $dst_h=id$resp_h, $dst_p=id$resp_p], 30sec);
	Pacf::drop_address(id$orig_h, 15sec);
	}
