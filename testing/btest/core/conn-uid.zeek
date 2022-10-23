#
# In "normal" test mode, connection uids should be deterministic.
#
# @TEST-EXEC: zeek -b -D -C -r $TRACES/wikipedia.trace %INPUT >output
# @TEST-EXEC: btest-diff output
#
# Without a seed, they should differ each time:
#
# @TEST-EXEC: unset ZEEK_SEED_FILE && unset BRO_SEED_FILE && zeek -b -C -r $TRACES/wikipedia.trace %INPUT >output2
# @TEST-EXEC: cat output output2 | sort | uniq -c | wc -l | sed 's/ //g' >counts
# @TEST-EXEC: btest-diff counts

@load base/protocols/http

event new_connection(c: connection)
	{
	print c$id, c$uid;
	}

event connection_established(c: connection)
	{
	print c$id, c$uid;
	}
