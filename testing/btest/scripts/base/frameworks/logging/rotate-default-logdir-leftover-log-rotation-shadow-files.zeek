# @TEST-DOC: Test that .shadow files are picked up from Log::default_logdir.
# @TEST-EXEC: mkdir logs
# @TEST-EXEC: echo ".log" >> logs/.shadow.conn.log
# @TEST-EXEC: echo "my_rotation_postprocessor" >> logs/.shadow.conn.log
# @TEST-EXEC: echo "leftover conn log" > logs/conn.log
# @TEST-EXEC: echo ".log" >> logs/.shadow.dns.log
# @TEST-EXEC: echo "my_rotation_postprocessor" >> logs/.shadow.dns.log
# @TEST-EXEC: echo "leftover dns log" > logs/dns.log

# @TEST-EXEC: zeek -b %INPUT > out

# @TEST-EXEC: ! test -f logs/.shadow.conn.log
# @TEST-EXEC: ! test -f logs/conn.log
# @TEST-EXEC: ! test -f logs/.shadow.dns.log
# @TEST-EXEC: ! test -f logs/dns.log

# Ensure rotated logs ends-up in the ./logs directory.
# @TEST-EXEC: cat ./logs/conn-*.log ./logs/dns-*.log > logs.cat

# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff out
# @TEST-EXEC: btest-diff logs.cat

module GLOBAL;

function my_rotation_postprocessor(info: Log::RotationInfo) : bool
	{
	print fmt("running my rotation postprocessor for path '%s'", info$path);
	return T;
	}

redef LogAscii::enable_leftover_log_rotation = T;
redef Log::default_logdir = "./logs";
redef Log::default_rotation_interval = 1hr;
redef Log::default_rotation_postprocessor_cmd = "echo";
