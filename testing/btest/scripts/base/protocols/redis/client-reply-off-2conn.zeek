# @TEST-DOC: Test CLIENT REPLY OFF, but turns on with new connection
# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: zeek -b -Cr $TRACES/redis/reply-off-on-2conn.pcap %INPUT >output
# @TEST-EXEC: btest-diff redis.log

@load base/protocols/redis
