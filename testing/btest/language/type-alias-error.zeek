# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: btest-diff-remove-abspath .stderr

type mac: stringA;

event zeek_init()
{
	print fmt ("hello");
}
