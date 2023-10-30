# @TEST-DOC: Check for regression of "when" capture confusion over outer scope
#
# @TEST-EXEC: zeek -b %INPUT | sort >out
# @TEST-EXEC: btest-diff out

module Test;

event zeek_init()
	{
	local myset = set(10.0.0.1, 10.0.0.2);

	when [myset] (T)
		{
		for ( ip in myset )
			{
			when [ip] ( ip == ip )
				{
				print fmt("%s", ip);
				}
			}
		}
	}
