# @TEST-DOC: Test Zeek parsing pubsub commands
# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: zeek -b -Cr $TRACES/redis/pubsub.pcap %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff redis.log

# Testing the example of pub sub in REDIS docs:
# https://redis.io/docs/latest/develop/interact/pubsub/
# These are just commands between two different clients, one PUBLISH and one SUBSCRIBE

@load base/protocols/redis
