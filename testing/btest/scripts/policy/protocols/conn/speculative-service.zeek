# A basic test of the speculative service detection

# @TEST-EXEC: zeek -b -C -r $TRACES/http/http-post-large.pcap %INPUT
# @TEST-EXEC: mv conn.log conn-post-large.log
# @TEST-EXEC: btest-diff conn-post-large.log

# @TEST-EXEC: zeek -b -C -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: mv conn.log conn-wiki.log
# @TEST-EXEC: btest-diff conn-wiki.log

@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load protocols/conn/speculative-service
