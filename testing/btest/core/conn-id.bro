#
# In "normal" test mode, connection uids should be determistic.
#
# @TEST-EXEC: bro -C -r $TRACES/wikipedia.trace %INPUT conn >output
# @TEST-EXEC: btest-diff output
#
# Without a seed, they should differ each time:
#
# @TEST-EXEC: unset BRO_SEED_FILE &&  bro -C -r $TRACES/wikipedia.trace %INPUT tcp >output2
# @TEST-EXEC: cat output output2 | sort | uniq -c | wc -l >counts
# @TEST-EXEC: btest-diff counts
#
# Make sure it works without the connection compressor as well.
#
# @TEST-EXEC: bro -C -r $TRACES/wikipedia.trace %INPUT tcp use_connection_compressor=F >output.cc
# @TEST-EXEC: btest-diff output.cc
#
# Make sure it works with the full connection compressor as well.
#
# @TEST-EXEC: bro -C -r $TRACES/wikipedia.trace %INPUT tcp cc_handle_only_syns=F >output.cc2
# @TEST-EXEC: btest-diff output.cc2


event new_connection(c: connection)
	{
	print c$id, c$uid;
	}

event connection_established(c: connection)
	{
	print c$id, c$uid;
	}
