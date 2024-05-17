# @TEST-DOC: Assert statement testing with assertion_failure and assertion_result implementation.
#
# Doesn't make sense for ZAM as it ignores assert's.
# @TEST-REQUIRES: test "${ZEEK_ZAM}" != "1"
#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

# Hook is not calling break: Reporter log is produced.
hook assertion_failure(cond: string, msg: string, bt: Backtrace)
	{
	print "assertion_failure", cond, msg, bt[0]$file_location, bt[0]$line_location;
	}

event zeek_init()
	{
	assert 1 != 1;
	print "not reached";
	}

@TEST-START-NEXT
# Test the backtrace location, also calling break to suppress reporter log.
hook assertion_failure(cond: string, msg: string, bt: Backtrace)
	{
	print "assertion_failure", cond, msg;
	local indent = "";
	for ( _, e in bt )
		{
		local file_name = e?$file_location ? e$file_location : "<none>";
		local line_number = e?$line_location ? e$line_location : 0;
		print fmt("%s%s %s:%s", indent, e$function_name, file_name, line_number);
		indent = fmt("%s ", indent);
		}

	break;
	}


function f()
	{
	assert sha1_hash("x") == "11f6ad8ec52a2984abaafd7c3b516503785c2072";
	assert to_count("5") == 4, fmt("5 is not 4");
	assert sha1_hash("") == "da39a3ee5e6b4b0d3255bfef95601890afd80709";
	}

function g() { f(); }
function h() { g(); }

event zeek_init()
	{
	h();
	print "not reached";
	}

@TEST-START-NEXT
# Calling terminate() from the assertion hook.
redef exit_only_after_terminate = T;

hook assertion_failure(cond: string, msg: string, bt: Backtrace)
	{
	print "assertion_failure", msg;
	terminate();
	}

event zeek_init()
	{
	assert F, "terminate me!";
	print "not reached";
	}

event zeek_done()
	{
	print "zeek_done()";
	assert zeek_is_terminating(), "zeek_done() should have zeek terminating";
	}

@TEST-START-NEXT
# Calling exit() from the assertion hook.
redef exit_only_after_terminate = T;

hook assertion_failure(cond: string, msg: string, bt: Backtrace)
	{
	print "assertion_failure", msg;
	exit(0);  # in real tests use exit(1), this is to please btest.
	}

event zeek_init()
	{
	assert F, "calling exit!";
	print "not reached";
	}

event zeek_done()
	{
	assert F, "zeek_done() not executed with exit()";
	}

@TEST-START-NEXT
global assertion_failures = 0;
global assertions_total = 0;

hook assertion_failure(cond: string, msg: string, bt: Backtrace)
	{
	print fmt("assertion_failure at %s:%s: %s%s%s",
	          bt[0]$file_location, bt[0]$line_location,
	          cond, |msg| > 0 ? " - " : "", msg);

	++assertion_failures;
	break;
	}

hook assertion_result(result: bool, cond: string, msg: string, bt: Backtrace)
	{
	print fmt("assertion_result %s at %s:%s: %s%s%s",
	          result, bt[0]$file_location, bt[0]$line_location,
	          cond, |msg| > 0 ? " - " : "", msg);

	++assertions_total;
	}

event zeek_test()
	{
	assert sha1_hash("x") == "11f6ad8ec52a2984abaafd7c3b516503785c2072";
	}

event zeek_test()
	{
	assert sha1_hash("") == "da39a3ee5e6b4b0d3255bfef95601890afd80709";
	}

event zeek_test()
	{
	assert sha1_hash("") == "wrong";
	}

event zeek_test()
	{
	assert sha1_hash("x") == "wrong";
	}

event zeek_init()
	{
	event zeek_test();
	}

event zeek_done()
	{
	print fmt("%d of %d assertions failed", assertion_failures, assertions_total);
	}

@TEST-START-NEXT
# Evaluating the msg expression can cause errors, see if we deal
# with that gracefully.
hook assertion_failure(cond: string, msg: string, bt: Backtrace)
	{
	print "assertion_failure", cond, msg, bt[0]$file_location, bt[0]$line_location;
	}

hook assertion_result(result: bool, cond: string, msg: string, bt: Backtrace)
	{
	print "assertion_result", result, cond, msg, bt[0]$file_location, bt[0]$line_location;
	}

event zeek_init()
	{
	assert 2 + 2 == 4, cat(get_current_packet_header()$ip);
	assert 2 + 2 == 4, to_json([$msg="true and works"]);
	assert 2 + 2 == 5, cat(get_current_packet_header()$ip);
	}

event zeek_done()
	{
	assert 2 + 2 == 5, to_json([$msg="false and works"]);
	assert 2 + 2 == 5, cat(get_current_packet_header()$ip);
	}

@TEST-START-NEXT
# Breaking in assertion_result() also suppresses the reporter errors.
hook assertion_result(result: bool, cond: string, msg: string, bt: Backtrace)
	{
	print "assertion_result", result, cond, msg, bt[0]$file_location, bt[0]$line_location;
	break;
	}

event zeek_init()
	{
	assert 2 + 2 == 4, "this is true";
	assert 2 + 2 == 4, to_json([$msg="this is also true"]);
	assert 2 + 2 == 5, "this is false";
	print "not reached";
	}

event zeek_done()
	{
	assert 2 + 2 == 5, "this is false";
	print "not reached";
	}

@TEST-START-NEXT
# Ensure cond is only evaluated once.
hook assertion_result(result: bool, cond: string, msg: string, bt: Backtrace)
	{
	print "assertion_result", result, cond, msg, bt[0]$file_location, bt[0]$line_location;
	break;
	}

function always_true(): bool
	{
	print "returning true";
	return T;
	}

function always_false(): bool
	{
	print "returning false";
	return F;
	}

event zeek_init()
	{
	print "zeek_init";
	assert always_true(), "always true";
	assert always_false(), "always false";
	print "not reached";
	}
