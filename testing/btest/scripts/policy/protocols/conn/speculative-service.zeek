# A basic test of the speculative service detection

# @TEST-EXEC: zeek -C -r $TRACES/http/http-post-large.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log

@load protocols/conn/speculative-service
