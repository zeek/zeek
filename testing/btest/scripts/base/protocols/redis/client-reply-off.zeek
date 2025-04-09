# @TEST-DOC: Test CLIENT REPLY OFF then ON again and a SKIP
# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: zeek -b -Cr $TRACES/redis/reply-off-on.pcap %INPUT >output
# @TEST-EXEC: btest-diff redis.log

@load base/protocols/redis
