# @TEST-DOC: Test Zeek parsing "pipelined" data responses
# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: zeek -b -Cr $TRACES/redis/excessive-pipelining.pcap %INPUT >output
# @TEST-EXEC: btest-diff redis.log
# @TEST-EXEC: btest-diff weird.log

@load base/protocols/redis

# Make sure we get a weird if we go over the pipelining threshold (intentionally limited)
redef Redis::max_pending_requests = 5;
