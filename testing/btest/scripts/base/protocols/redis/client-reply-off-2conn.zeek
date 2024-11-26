# @TEST-DOC: Test CLIENT REPLY OFF, but turns on with new connection
#
# @TEST-EXEC: zeek -Cr $TRACES/redis/reply-off-on-2conn.pcap base/protocols/redis %INPUT >output
# @TEST-EXEC: btest-diff redis.log
