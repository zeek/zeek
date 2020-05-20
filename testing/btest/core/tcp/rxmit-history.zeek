# @TEST-EXEC: zeek -C -r $TRACES/tcp/retransmit-fast009.trace %INPUT && mv conn.log conn-1.log
# @TEST-EXEC: zeek -C -r $TRACES/wikipedia.trace %INPUT && mv conn.log conn-2.log
# @TEST-EXEC: btest-diff conn-1.log
# @TEST-EXEC: btest-diff conn-2.log

