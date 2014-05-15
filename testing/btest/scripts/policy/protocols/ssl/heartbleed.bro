# TEST-EXEC: bro -C -r $TRACES/tls/heartbleed.pcap %INPUT
# TEST-EXEC: mv notice.log notice-heartbleed.log
# TEST-EXEC: btest-diff notice-heartbleed.log

# @TEST-EXEC: bro -C -r $TRACES/tls/heartbleed-success.pcap %INPUT
# @TEST-EXEC: mv notice.log notice-heartbleed-success.log
# @TEST-EXEC: btest-diff notice-heartbleed-success.log

# @TEST-EXEC: bro -C -r $TRACES/tls/heartbleed-encrypted-success.pcap %INPUT
# @TEST-EXEC: mv notice.log notice-encrypted.log
# @TEST-EXEC: btest-diff notice-encrypted.log

@load protocols/ssl/heartbleed
