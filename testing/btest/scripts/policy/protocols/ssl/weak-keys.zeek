# @TEST-EXEC: zeek -r $TRACES/tls/dhe.pcap %INPUT
# @TEST-EXEC: cp notice.log notice-out.log
# @TEST-EXEC: zeek -r $TRACES/tls/ssl-v2.trace %INPUT
# @TEST-EXEC: cat notice.log >> notice-out.log
# @TEST-EXEC: zeek -r $TRACES/tls/ssl.v3.trace %INPUT
# @TEST-EXEC: cat notice.log >> notice-out.log
# @TEST-EXEC: btest-diff notice-out.log

@load protocols/ssl/weak-keys

redef SSL::notify_weak_keys = ALL_HOSTS;
redef SSL::notify_minimal_key_length = 4096;
