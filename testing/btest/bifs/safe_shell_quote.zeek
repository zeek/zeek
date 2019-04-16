#
# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local a = "echo `pwd` ${TEST} > \"my file\"; echo -e \"\\n\"";
	print a;

	local b = safe_shell_quote(a);
	print b;
	}
