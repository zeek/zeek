#
# @TEST-EXEC: bro %INPUT
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: btest-diff reporter.log

event bro_init()
	{
	print strptime("%Y-%m-%d", "2012-10-19");
	print strptime("%m", "1980-10-24");
	}