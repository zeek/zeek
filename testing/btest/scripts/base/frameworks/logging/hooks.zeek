# Tests for policy hooks on log filters.
#
# @TEST-EXEC: zeek -b test.zeek %INPUT
# @TEST-EXEC: btest-diff test.log
# @TEST-EXEC: test -f other.log && btest-diff other.log || true

@TEST-START-FILE test.zeek
# This provides a simple test module harness, used by all of the individual tests below.
module Test;

export {
	# Create a new ID for our log stream
	redef enum Log::ID += { LOG, LOG_OTHER };

	# Create a corresponding policy hook:
	global log_policy: Log::PolicyHook;

	# Make up a log format for our tests
	type Info: record {
		t: time;
		status: string;
	} &log;
}

event zeek_init() &priority=2
	{
	Log::create_stream(Test::LOG, [$columns=Info, $path="test", $policy=log_policy]);
	Log::create_stream(Test::LOG_OTHER, [$columns=Info, $path="test_other"]);
	}
@TEST-END-FILE test.zeek

# Verify basic argument passing -- id and filter should be accessible
# and have expected values. The hook should not catch.

hook Test::log_policy(rec: Test::Info, id: Log::ID, filter: Log::Filter)
	{
	if ( id != Test::LOG || filter$name != "default" )
		break;
	}

event zeek_init()
	{
	Log::write(Test::LOG, [$t=network_time(), $status="foo"]);
	}

@TEST-START-NEXT

# Verify that a policy hook can veto select log records.

hook Test::log_policy(rec: Test::Info, id: Log::ID, filter: Log::Filter)
	{
	if ( rec$status == "foo" )
		break;
	}

event zeek_init()
	{
	Log::write(Test::LOG, [$t=network_time(), $status="foo"]);
	Log::write(Test::LOG, [$t=network_time(), $status="bar"]);
	}

@TEST-START-NEXT

# Verify that a policy hook can alter the log entry.
#
# NOTE: doing this is dangerous; the change survives into log writes
# resulting on other filters that get processed after the current one,
# and the order of filters is undefined. We just test here that the
# modification doesn't cause unexpected errors.

hook Test::log_policy(rec: Test::Info, id: Log::ID, filter: Log::Filter)
	{
	rec$status = "bar";
	}

event zeek_init()
	{
	Log::write(Test::LOG, [$t=network_time(), $status="foo"]);
	}

@TEST-START-NEXT

# Verify that multiple hook handlers can get registered and their
# priorities work as expected. (More of a generic hook test than
# logging-specific, really.)
#
# The higher-priority hook filters out the only log record; the
# lower-priority one should not get an opportunity to change it.

hook Test::log_policy(rec: Test::Info, id: Log::ID, filter: Log::Filter) &priority=10
	{
	if ( rec$status == "foo" )
		rec$status = "baz";
	}

hook Test::log_policy(rec: Test::Info, id: Log::ID, filter: Log::Filter) &priority=20
	{
	rec$status = "bar";
	}

event zeek_init()
	{
	Log::write(Test::LOG, [$t=network_time(), $status="foo"]);
	}

@TEST-START-NEXT

# Verify that the stream-level policy gets inherited into additional
# filters.  The single hook handler should get invoked for both of the
# log filters, and alters them depending on the filter.

hook Test::log_policy(rec: Test::Info, id: Log::ID, filter: Log::Filter)
	{
	if ( filter$name == "default" )
		rec$status = "bar";
	if ( filter$name == "other" )
		rec$status = "baz";
	}

event zeek_init()
	{
	Log::add_filter(Test::LOG, [$name="other", $path="other"]);
	Log::write(Test::LOG, [$t=network_time(), $status="foo"]);
	}

@TEST-START-NEXT

# Verify that filters can override the stream-level policy. The
# stream-level policy rejects select records; the overriding one is
# permissive.

hook Test::log_policy(rec: Test::Info, id: Log::ID, filter: Log::Filter)
	{
	if ( rec$status == "foo" )
		break;
	}

hook log_policy_permissible(rec: Test::Info, id: Log::ID, filter: Log::Filter)
	{
	}

event zeek_init()
	{
	Log::add_filter(Test::LOG, [$name="other", $path="other", $policy=log_policy_permissible]);
	Log::write(Test::LOG, [$t=network_time(), $status="foo"]);
	Log::write(Test::LOG, [$t=network_time(), $status="bar"]);
	}

@TEST-START-NEXT

# Verify that filters can define their own policy hooks when the
# stream doesn't provide any. The Test::LOG_OTHER stream does not.

hook my_log_policy(rec: Test::Info, id: Log::ID, filter: Log::Filter)
	{
	if ( rec$status == "foo" )
		break;
	}

event zeek_init()
	{
	local filter = Log::get_filter(Test::LOG_OTHER, "default");
	filter$path = "test";
	filter$policy = my_log_policy;
	Log::add_filter(Test::LOG_OTHER, filter);

	Log::write(Test::LOG_OTHER, [$t=network_time(), $status="foo"]);
	Log::write(Test::LOG_OTHER, [$t=network_time(), $status="bar"]);
	}
