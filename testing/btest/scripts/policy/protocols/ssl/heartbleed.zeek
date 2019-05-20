# TEST-EXEC: zeek -C -r $TRACES/tls/heartbleed.pcap %INPUT
# TEST-EXEC: mv notice.log notice-heartbleed.log
# TEST-EXEC: btest-diff notice-heartbleed.log

# @TEST-EXEC: zeek -C -r $TRACES/tls/heartbleed-success.pcap %INPUT
# @TEST-EXEC: mv notice.log notice-heartbleed-success.log
# @TEST-EXEC: btest-diff notice-heartbleed-success.log

# @TEST-EXEC: zeek -C -r $TRACES/tls/heartbleed-encrypted.pcap %INPUT
# @TEST-EXEC: mv notice.log notice-encrypted.log
# @TEST-EXEC: btest-diff notice-encrypted.log

# @TEST-EXEC: zeek -C -r $TRACES/tls/heartbleed-encrypted-success.pcap %INPUT
# @TEST-EXEC: mv notice.log notice-encrypted-success.log
# @TEST-EXEC: btest-diff notice-encrypted-success.log

# @TEST-EXEC: zeek -C -r $TRACES/tls/heartbleed-encrypted-short.pcap %INPUT
# @TEST-EXEC: mv notice.log notice-encrypted-short.log
# @TEST-EXEC: btest-diff notice-encrypted-short.log

@load protocols/ssl/heartbleed
