# @TEST-DOC: Test Zeek with RESP over TLS so it doesn't get gibberish
# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: zeek -b -Cr $TRACES/redis/tls.pcap %INPUT >output
# @TEST-EXEC-FAIL: test -f redis.log

# The logs should probably be empty since it's all encrypted

@load base/protocols/redis
