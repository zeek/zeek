# @TEST-EXEC: bro -r $TRACES/tls/ecdhe.pcap %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER='grep -v ^# | $SCRIPTS/diff-sort' btest-diff netcontrol.log

@load base/frameworks/netcontrol

event NetControl::init()
	{
	local netcontrol_debug = NetControl::create_debug(T);
	NetControl::activate(netcontrol_debug, 0);
	}

module NetControl;

event connection_established(c: connection)
	{
	local id = c$id;
	NetControl::drop_address_catch_release(id$orig_h);
	# second one should be ignored because duplicate
	NetControl::drop_address_catch_release(id$orig_h);

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

