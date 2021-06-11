# @TEST-EXEC: zeek -b -r $TRACES/smtp.trace %INPUT
# @TEST-EXEC: btest-diff .stdout

event net_done(t: time)
	{
	print get_conn_stats();
	}