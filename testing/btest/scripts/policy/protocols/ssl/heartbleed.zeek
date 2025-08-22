# @TEST-EXEC: ZEEKPATH=$ZEEKPATH:$SCRIPTS zeek -b -C -r $TRACES/tls/heartbleed-encrypted.pcap %INPUT
# @TEST-EXEC: mv notice.log notice-encrypted.log

# @TEST-EXEC: ZEEKPATH=$ZEEKPATH:$SCRIPTS zeek -b -C -r $TRACES/tls/heartbleed-encrypted-success.pcap %INPUT
# @TEST-EXEC: mv notice.log notice-encrypted-success.log

# @TEST-EXEC: ZEEKPATH=$ZEEKPATH:$SCRIPTS zeek -b -C -r $TRACES/tls/heartbleed-encrypted-short.pcap %INPUT
# @TEST-EXEC: mv notice.log notice-encrypted-short.log

# @TEST-EXEC: ZEEKPATH=$ZEEKPATH:$SCRIPTS zeek -b -C -r $TRACES/tls/heartbleed.pcap %INPUT
# @TEST-EXEC: mv notice.log notice-heartbleed.log

# @TEST-EXEC: ZEEKPATH=$ZEEKPATH:$SCRIPTS zeek -b -C -r $TRACES/tls/heartbleed-success.pcap %INPUT
# @TEST-EXEC: mv notice.log notice-heartbleed-success.log

# @TEST-EXEC: btest-diff notice-encrypted.log
# @TEST-EXEC: btest-diff notice-encrypted-success.log
# @TEST-EXEC: btest-diff notice-encrypted-short.log
# @TEST-EXEC: btest-diff notice-heartbleed.log
# @TEST-EXEC: btest-diff notice-heartbleed-success.log

@load protocols/ssl/heartbleed

# @TEST-START-NEXT:
@load protocols/ssl/heartbleed
@load disable-ssl-analyzer-after-max-count
