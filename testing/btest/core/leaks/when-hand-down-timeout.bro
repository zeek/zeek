# Needs perftools support.
#
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: bro  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run bro bro -b -m %INPUT
# @TEST-EXEC: btest-bg-wait 60

#  Check that a higer level timeout abort lower-level triggers.

@load base/utils/exec
@load base/frameworks/communication # let network-time run. otherwise there are no heartbeats...
redef exit_only_after_terminate = T;

global correct_termination = F;

event termination()
	{
	if ( ! correct_termination )
		{
		print("wrong termination");
		terminate();
		}
	}

event bro_init()
	{
	schedule 2secs { termination() };
	
	local stall = Exec::Command($cmd="sleep 30");

	when ( local result2 = Exec::run(stall) )
		{
		print "shouldn't get here", result2;
		}
	timeout 0.1 sec
		{
		print "timeout";
		correct_termination = T;
		terminate();
		}
	}
