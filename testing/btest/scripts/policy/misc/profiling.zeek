# @TEST-DOC: Verify loading of the resource profiler with different Zeek terminations.
# @TEST-EXEC: zeek -b %INPUT policy/misc/profiling
# @TEST-EXEC: test -f prof.log

# @TEST-START-NEXT
# A direct exit used to crash Zeek, see GH#5872.

event zeek_init()
	{
	exit(0);
	}
