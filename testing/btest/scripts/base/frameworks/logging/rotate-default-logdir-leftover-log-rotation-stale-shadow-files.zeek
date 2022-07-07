# @TEST-DOC: Test that stale .shadow files are removed from ::default_logdir
# @TEST-EXEC: mkdir logs
# @TEST-EXEC: echo ".log" >> logs/.shadow.conn.log
# @TEST-EXEC: echo "my_rotation_postprocessor" >> logs/.shadow.conn.log

# @TEST-EXEC: zeek -b %INPUT > out 2>&1

# @TEST-EXEC: ! test -f logs/.shadow.conn.log

# @TEST-EXEC: TEST_DIFF_CANONIFIER='$SCRIPTS/diff-remove-abspath | $SCRIPTS/diff-remove-timestamps' btest-diff out

module GLOBAL;

function my_rotation_postprocessor(info: Log::RotationInfo) : bool
	{
	print fmt("running my rotation postprocessor for path '%s'", info$path);
	return T;
	}

redef Log::default_logdir = "./logs";
redef LogAscii::enable_leftover_log_rotation = T;
redef Log::default_rotation_interval = 1hr;
redef Log::default_rotation_postprocessor_cmd = "echo";
