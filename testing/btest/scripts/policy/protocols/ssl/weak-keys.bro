# @TEST-EXEC: bro -r $TRACES/tls/dhe.pcap %INPUT
# @TEST-EXEC: btest-diff notice.log

@load protocols/ssl/weak-keys

redef SSL::notify_weak_keys = ALL_HOSTS;
redef SSL::notify_minimal_key_length = 4096;
