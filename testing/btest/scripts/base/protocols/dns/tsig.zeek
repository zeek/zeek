# @TEST-EXEC: zeek -r $TRACES/dns-tsig.trace %INPUT >out
# @TEST-EXEC: btest-diff out

redef dns_skip_all_addl = F;

event dns_TSIG_addl(c: connection, msg: dns_msg, ans: dns_tsig_additional)
	{
	print ans;
	print |ans$sig|;
	}
