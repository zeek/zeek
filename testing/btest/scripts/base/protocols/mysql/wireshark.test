# This tests a PCAP with a few MySQL commands from the Wireshark samples.

# @TEST-EXEC: zeek -b -r $TRACES/mysql/mysql.trace %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff mysql.log

@load base/protocols/mysql

event mysql_ok(c: connection, affected_rows: count)
	{
	print "mysql ok", affected_rows;
	}

event mysql_result_row(c: connection, row: string_vec)
	{
	print "mysql result row", row;
	}

event mysql_error(c: connection, code: count, msg: string)
	{
	print "mysql error", code, msg;
	}

event mysql_command_request(c: connection, command: count, arg: string)
	{
	print "mysql request", command, arg;
	}
