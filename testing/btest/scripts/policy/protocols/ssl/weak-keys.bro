# @TEST-EXEC: bro -r $TRACES/tls/dhe.pcap %INPUT
# @TEST-EXEC: mv notice.log notice-1.log
# @TEST-EXEC: btest-diff notice-1.log

@load protocols/ssl/weak-keys

redef SSL::notify_weak_keys = ALL_HOSTS;
redef SSL::notify_minimal_key_length = 4096;
