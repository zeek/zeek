# @TEST-EXEC-FAIL: zeek -b %INPUT 2>out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
#
# @TEST-DOC: Ensures tables without square brackets around keys error
 
event zeek_init()
	{
	print table("SSH" = 22/tcp, "HTTPS" = 443/tcp);
	local x = table("one" = 1, "two" = 2);
	}
