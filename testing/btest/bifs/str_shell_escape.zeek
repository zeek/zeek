#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local a = "echo ${TEST} > \"my file\"";

	print |a|;
	print a;

	local b = str_shell_escape(a);
	print |b|;
	print b;
	}
