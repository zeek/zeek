# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: bro  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run bro -b bro -m %INPUT
# @TEST-EXEC: btest-bg-wait 60

# Input framework needs this.
@load base/frameworks/communication

@load base/utils/exec

event x()
	{
	print("X");
	}

event bro_init()
	{
	schedule 1sec { x() };
	local result = async Exec::run([$cmd="sleep 2; echo test"]);
	print(result);
	}
