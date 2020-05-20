# A basic test of the speculative service detection

# @TEST-EXEC: zeek -C -r $TRACES/http/http-post-large.pcap %INPUT
# @TEST-EXEC: mv conn.log conn-post-large.log
# @TEST-EXEC: btest-diff conn-post-large.log

# @TEST-EXEC: zeek -C -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: mv conn.log conn-wiki.log
# @TEST-EXEC: btest-diff conn-wiki.log

@load protocols/conn/speculative-service
