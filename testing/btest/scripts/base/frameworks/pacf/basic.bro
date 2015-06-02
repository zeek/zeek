# @TEST-EXEC: bro -r $TRACES/smtp.trace %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER='grep -v ^# | $SCRIPTS/diff-sort' btest-diff pacf.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff .stdout

@load base/frameworks/pacf

event bro_init()
	{
	local pacf_debug = Pacf::create_debug(T);
	Pacf::activate(pacf_debug, 0);
	}

event connection_established(c: connection)
	{
	local id = c$id;
	Pacf::shunt_flow([$src_h=id$orig_h, $src_p=id$orig_p, $dst_h=id$resp_h, $dst_p=id$resp_p], 30sec);
	Pacf::drop_address(id$orig_h, 15sec);
	Pacf::whitelist_address(id$orig_h, 15sec);
	Pacf::redirect_flow([$src_h=id$orig_h, $src_p=id$orig_p, $dst_h=id$resp_h, $dst_p=id$resp_p], 5, 30sec);
	}
