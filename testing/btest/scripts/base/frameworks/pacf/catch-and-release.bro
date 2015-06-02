# @TEST-EXEC: bro -r $TRACES/smtp.trace %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER='grep -v ^# | $SCRIPTS/diff-sort' btest-diff pacf.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff .stdout

@load base/frameworks/pacf

event bro_init()
	{
	local pacf_debug = Pacf::create_debug(T);
	Pacf::activate(pacf_debug, 0);
	}

module Pacf;

event connection_established(c: connection)
	{
	local id = c$id;
	Pacf::drop_address_catch_release(id$orig_h);
	# second one should be ignored because duplicate
	Pacf::drop_address_catch_release(id$orig_h);

	# mean call directly into framework - simulate new connection
	delete current_blocks[id$orig_h];
	check_conn(id$orig_h);
	delete current_blocks[id$orig_h];
	check_conn(id$orig_h);
	delete current_blocks[id$orig_h];
	check_conn(id$orig_h);
	delete current_blocks[id$orig_h];
	check_conn(id$orig_h);
	}

