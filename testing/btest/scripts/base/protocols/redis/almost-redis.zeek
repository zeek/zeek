# @TEST-DOC: Test 2 commands that look like RESP, then server responses don't
# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: zeek -b -r $TRACES/redis/almost-resp.pcap %INPUT >output
# @TEST-EXEC: btest-diff redis.log
#
# Really, the first 2 ARE Redis. The later ones should not be logged because we
# realized it's not Redis. The output from the server is:
# +OK\r\n+OK\r\nnot RESP\r\nStill not RESP\r\nNope\r\n

@load base/protocols/redis
