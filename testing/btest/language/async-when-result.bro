# TODO: Hangs with "bro -b"
# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

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
