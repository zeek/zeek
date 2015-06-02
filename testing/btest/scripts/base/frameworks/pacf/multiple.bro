# @TEST-EXEC: bro -r $TRACES/smtp.trace %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER='grep -v ^# | $SCRIPTS/diff-sort' btest-diff pacf.log

@load base/frameworks/pacf

event bro_init()
	{
	local pacf_debug = Pacf::create_debug(T);
	local pacf_debug_2 = Pacf::create_debug(T);
	local of_controller = OpenFlow::log_new(42);
	local pacf_of = Pacf::create_openflow(of_controller);
	Pacf::activate(pacf_debug, 10);
	Pacf::activate(pacf_of, 10);
	Pacf::activate(pacf_debug_2, 0);
	}

event connection_established(c: connection)
	{
	local id = c$id;
	Pacf::shunt_flow([$src_h=id$orig_h, $src_p=id$orig_p, $dst_h=id$resp_h, $dst_p=id$resp_p], 30sec);
	Pacf::drop_address(id$orig_h, 15sec);
	Pacf::whitelist_address(id$orig_h, 15sec);
	Pacf::redirect_flow([$src_h=id$orig_h, $src_p=id$orig_p, $dst_h=id$resp_h, $dst_p=id$resp_p], 5, 30sec);
	}
