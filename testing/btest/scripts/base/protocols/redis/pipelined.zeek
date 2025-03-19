# @TEST-DOC: Test Zeek parsing "pipelined" data responses
# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: zeek -b -Cr $TRACES/redis/pipelining-example.pcap %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff redis.log

# Testing the example of "pipelining" in REDIS docs:
# https://redis.io/docs/latest/develop/use/pipelining/
# Namely sending three PINGs. This does not get sent as RESP data, but we should
# be able to skip it and get the responses, which are properly encoded.
#
# Also, you can send serialized data this way - that's kinda what the bulk test does.

@load base/protocols/redis
