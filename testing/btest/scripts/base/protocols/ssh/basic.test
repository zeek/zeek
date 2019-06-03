# This tests some SSH connections and the output log.

# @TEST-EXEC: zeek -r $TRACES/ssh/ssh.trace %INPUT
# @TEST-EXEC: btest-diff ssh.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff .stdout

event ssh_auth_result(c: connection, result: bool, auth_attempts: count)
	{
	print "auth_result", c$uid, result, auth_attempts;
	}
