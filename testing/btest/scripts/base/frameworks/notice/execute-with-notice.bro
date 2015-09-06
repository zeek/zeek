# Test that execute_with_notice() executes a program with env. vars. of
# the form BRO_ARG_<field>.

# @TEST-EXEC: bro %INPUT > out 2>&1
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local c = conn_id($orig_h = 192.168.10.1, $orig_p = 10/tcp, $resp_h = 192.168.10.2, $resp_p = 11/tcp);

	# Construct a record with some fields assigned a value (chosen to test a
	# variety of data types).
	local n = Notice::Info($id = c, $proto = tcp, $note = Notice::Tally, $msg = "Test", $src = 192.168.1.2, $p = 123/tcp, $n = 7, $actions = set(Notice::ACTION_NONE));

	Notice::execute_with_notice("bash mytest", n);
	}

@TEST-START-FILE mytest
set | grep BRO_ARG_
@TEST-END-FILE
