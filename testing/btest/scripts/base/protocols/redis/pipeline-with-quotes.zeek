# @TEST-DOC: Test Zeek parsing "pipelined" data responses
# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: zeek -b -Cr $TRACES/redis/pipeline-quotes.pcap %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff redis.log
# TODO: Make it so weird.log exists again with `zeek::weird` for inline commands
# btest-diff weird.log

# Tests unserialized data where quotes should make one token

@load base/protocols/redis
