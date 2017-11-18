# @TEST-EXEC: btest-bg-run bro "bro -b %INPUT >output 2>&1"
# @TEST-EXEC: btest-bg-wait 15
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-abspath | $SCRIPTS/diff-remove-timestamps | $SCRIPTS/diff-sort" btest-diff bro/output

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
