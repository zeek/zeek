# @TEST-DOC: ZAM cat() self-assignment must not corrupt managed string references.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b -O ZAM %INPUT >output 2>stderr
# @TEST-EXEC: test ! -s stderr

# "s = cat(s)" compiles to a Cat1 op sharing one frame slot for source and dest;
# churn many iterations so allocator reuse reliably surfaces any refcount bug.
function churn(n: count)
	{
	local i: count = 0;

	while ( i < n )
		{
		local s = fmt("%s-%d", "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",
		    i);
		s = cat(s);
		++i;
		}
	}

event zeek_init()
	{
	churn(10000);
	}
