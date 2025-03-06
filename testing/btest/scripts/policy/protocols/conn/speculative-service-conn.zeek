# Test logging of speculative service in service field

# @TEST-EXEC: zeek -b -C -r $TRACES/http/http-post-large.pcap %INPUT
# @TEST-EXEC: mv conn.log conn-post-large.log
# @TEST-EXEC: btest-diff conn-post-large.log

@load base/protocols/conn
@load base/protocols/http
@load protocols/conn/speculative-service

redef Conn::track_speculative_services_in_connection = T;
