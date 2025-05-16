# @TEST-DOC: Test Zeek parsing pubsub commands
# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: zeek -b -r $TRACES/redis/stream.pcap %INPUT >output
# @TEST-EXEC: btest-diff redis.log

# Streams like with XRANGE return arrays of bulk strings. We shouldn't count the
# response as commands.

@load base/protocols/redis
