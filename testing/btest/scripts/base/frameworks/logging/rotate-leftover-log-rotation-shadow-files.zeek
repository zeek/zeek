# @TEST-DOC: Enable leftover log rotation, put shadow files for conn and dns in the cwd and ensure rotation happens during startup.
# @TEST-EXEC: echo ".log" >> .shadow.conn.log
# @TEST-EXEC: echo "my_rotation_postprocessor" >> .shadow.conn.log
# @TEST-EXEC: echo "leftover conn log" > conn.log

# @TEST-EXEC: echo ".log" >> .shadow.dns.log
# @TEST-EXEC: echo "my_rotation_postprocessor" >> .shadow.dns.log
# @TEST-EXEC: echo "leftover dns log" > dns.log

# @TEST-EXEC: zeek -b %INPUT > out

# Ensure leftover files were removed.
# @TEST-EXEC: ! test -f .shadow.conn.log
# @TEST-EXEC: ! test -f conn.log
# @TEST-EXEC: ! test -f .shadow.dns.log
# @TEST-EXEC: ! test -f dns.log

# Ensure the rotated conn log ends-up in the current working directory.
# @TEST-EXEC: ls ./conn-*.log
# @TEST-EXEC: cat ./conn-*.log ./dns-*.log > logs.cat

# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff out
# @TEST-EXEC: btest-diff logs.cat

module GLOBAL;

function my_rotation_postprocessor(info: Log::RotationInfo) : bool
	{
	print fmt("running my rotation postprocessor for path '%s'", info$path);
	return T;
	}

redef LogAscii::enable_leftover_log_rotation = T;
redef Log::default_rotation_interval = 1hr;
redef Log::default_rotation_postprocessor_cmd = "echo";
