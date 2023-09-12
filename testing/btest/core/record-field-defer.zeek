# @TEST-DOC: Nested records with non-const &defaults are not deferred initialized. Regression test for #3260
# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT >output
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff output

module Test;

global seq = 0;

function my_network_time(): time
	{
	++seq;
	print seq, "my_network_time() called", network_time();
	return network_time();
	}

type Inner: record {
	ts: time &default=my_network_time();
};

type State: record {
	ts: time &default=my_network_time();
	inner: Inner;
};

global tbl: table[string] of State;

event new_connection(c: connection)
	{
	print seq, "new_connection", c$uid, network_time();
	tbl[c$uid] = State();
	print seq, "new_connection done";
	}

event connection_state_remove(c: connection)
	{
	print seq, "connection_state_remove", c$uid, network_time();
	local s = tbl[c$uid];
	print seq, "state", c$uid, s;
	print seq, "connection_state_remove done";
	}

# @TEST-START-NEXT

# Same as before, but Inner contains two default fields

module Test;

global seq = 0;

function my_network_time(): time
	{
	++seq;
	print seq, "my_network_time() called", network_time();
	return network_time();
	}

type Inner: record {
	ts: time &default=my_network_time();
	ts_other: time &default=my_network_time();
};

type State: record {
	ts: time &default=my_network_time();
	inner: Inner;
};

global tbl: table[string] of State;

event new_connection(c: connection)
	{
	print seq, "new_connection", c$uid, network_time();
	tbl[c$uid] = State();
	print seq, "new_connection done";
	}

event connection_state_remove(c: connection)
	{
	print seq, "connection_state_remove", c$uid, network_time();
	local s = tbl[c$uid];
	print seq, "state", c$uid, s;
	print seq, "connection_state_remove done";
	}



# @TEST-START-NEXT

# Same as before, but Inner is instead redef'ed with non-const &default

module Test;

global seq = 0;

function my_network_time(): time
	{
	++seq;
	print seq, "my_network_time() called", network_time();
	return network_time();
	}

type Inner: record { };

type State: record {
	ts: time &default=my_network_time();
	inner: Inner;
};

redef record Inner += {
	ts: time &default=my_network_time();
};

global tbl: table[string] of State;

event new_connection(c: connection)
	{
	print seq, "new_connection", c$uid, network_time();
	tbl[c$uid] = State();
	print seq, "new_connection done";
	}

event connection_state_remove(c: connection)
	{
	print seq, "connection_state_remove", c$uid, network_time();
	local s = tbl[c$uid];
	print seq, "state", c$uid, s;
	print seq, "connection_state_remove done";
	}

# @TEST-START-NEXT

# Same as before, but State has two Inner fields and the Inner redef happens twice.

module Test;

global seq = 0;

function my_network_time(): time
	{
	++seq;
	print seq, "my_network_time() called", network_time();
	return network_time();
	}

type Inner: record { };

type State: record {
	ts: time &default=my_network_time();
	inner: Inner;
	inner_other: Inner;
};

redef record Inner += {
	ts: time &default=my_network_time();
};

redef record Inner += {
	ts_other: time &default=my_network_time();
};

global tbl: table[string] of State;

event new_connection(c: connection)
	{
	print seq, "new_connection", c$uid, network_time();
	tbl[c$uid] = State();
	print seq, "new_connection done";
	}

event connection_state_remove(c: connection)
	{
	print seq, "connection_state_remove", c$uid, network_time();
	local s = tbl[c$uid];
	print seq, "state", c$uid, s;
	print seq, "connection_state_remove done";
	}
