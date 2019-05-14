#
# In "normal" test mode, connection uids should be determistic.
#
# @TEST-EXEC: zeek -C -r $TRACES/wikipedia.trace %INPUT >output
# @TEST-EXEC: btest-diff output
#
# Without a seed, they should differ each time:
#
# @TEST-EXEC: unset BRO_SEED_FILE &&  zeek -C -r $TRACES/wikipedia.trace %INPUT >output2
# @TEST-EXEC: cat output output2 | sort | uniq -c | wc -l | sed 's/ //g' >counts
# @TEST-EXEC: btest-diff counts

event new_connection(c: connection)
	{
	print c$id, c$uid;
	}

event connection_established(c: connection)
	{
	print c$id, c$uid;
	}
