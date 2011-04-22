#
# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	local a = "X-Mailer: Testing Test (http://www.example.com)";
	print split1(a, /:[[:blank:]]*/);
	}
