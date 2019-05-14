# @TEST-EXEC: zeek -b -r $TRACES/ftp/ipv6.trace %INPUT >output
# @TEST-EXEC: btest-diff output

function print_connection(c: connection, event_name: string)
	{
	print fmt("%s: %s", event_name, c$id);
	print fmt("    orig_flow %d", c$orig$flow_label);
	print fmt("    resp_flow %d", c$resp$flow_label);
	}

event new_connection(c: connection)
	{
	print_connection(c, "new_connection");
	}

event connection_established(c: connection)
	{
	print_connection(c, "connection_established");
	}

event connection_state_remove(c: connection)
	{
	print_connection(c, "connection_state_remove");
	}

event connection_flow_label_changed(c: connection, is_orig: bool,
                                    old_label: count, new_label: count)
	{
	print_connection(c, fmt("connection_flow_label_changed(%s)",                             is_orig ? "orig" : "resp"));
	print fmt("    old_label %d", old_label);
	print fmt("    new_label %d", new_label);
	}
