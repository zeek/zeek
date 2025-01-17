# @TEST-DOC: Test lookup_connection() and connection_exists()
#
# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

event new_connection(c: connection)
	{
	local c2 = lookup_connection(c$id);
	assert c$uid == c2$uid;

	local cid: conn_id;
	cid$orig_h = c$id$orig_h;
	cid$orig_p = c$id$orig_p;
	cid$resp_h = c$id$resp_h;
	cid$resp_p = c$id$resp_p;

	# Produces an error on .stderr because cid$proto wasn't
	# initialized and then returns a dummy record.
	local c3 = lookup_connection(cid);
	assert c3$history == "";
	assert c3$id$orig_h == 0.0.0.0;
	assert c3$id$orig_p == 0/udp;

	cid$proto = c$id$proto;
	local c4 = lookup_connection(cid);
	assert c$uid == c4$uid;
	}

event new_connection(c: connection)
	{
	# This needs to hold.
	assert connection_exists(c$id);

	local my_id: conn_id;
	my_id$orig_h = c$id$orig_h;
	my_id$orig_p = c$id$orig_p;
	my_id$resp_h = c$id$resp_h;
	my_id$resp_p = c$id$resp_p;

	# Produces an error because cid$proto wasn't initialized.
	assert ! connection_exists(my_id);

	my_id$proto = c$id$proto;
	assert connection_exists(my_id);
	}

event new_connection(c: connection)
	{
	# This crashed previously!
	local my_id: conn_id;
	local c2 = lookup_connection(my_id);
	assert c2$history == "";
	assert c2$id$orig_h == 0.0.0.0;
	assert c2$id$orig_p == 0/udp;

	# This also crashed!
	assert ! connection_exists(my_id);
	}
