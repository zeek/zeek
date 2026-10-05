# @TEST-EXEC: zeek -b -r $TRACES/tls/google-duplicate.pcap %INPUT
# @TEST-EXEC: btest-diff ssl.log
# @TEST-EXEC: btest-diff x509.log
# @TEST-EXEC: btest-diff known_certs.log

# @TEST-EXEC: zeek -r $TRACES/tls/google-duplicate.pcap %INPUT storage-framework-config.zeek
# @TEST-EXEC: mv known_certs.log knowncerts-storage-framework.log
# @TEST-EXEC: btest-diff knowncerts-storage-framework.log

redef Cluster::default_store_dir = ".";

@load protocols/ssl/known-certs

redef Known::cert_tracking = ALL_HOSTS;

# @TEST-START-FILE storage-framework-config.zeek

redef Known::enable_certs_persistence=T;

# @TEST-END-FILE
