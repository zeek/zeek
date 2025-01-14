# @TEST-EXEC: zeek -b %INPUT >out 2>err
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff err

function myfunc1(a: addr, b: addr): int
	{
	}

print is_event_handled("zeek_init"); # T
print is_event_handled("dns_EDNS_cookie"); # F
print is_event_handled("myfunc1"); # builtin error
print is_event_handled("conn_id"); # builtin error
