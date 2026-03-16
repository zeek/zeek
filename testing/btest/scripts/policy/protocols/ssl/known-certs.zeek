# @TEST-REQUIRES: grep -q "#define HAVE_BROKER" $BUILD/zeek-config.h
# @TEST-EXEC: zeek -b -r $TRACES/tls/google-duplicate.pcap %INPUT
# @TEST-EXEC: btest-diff ssl.log
# @TEST-EXEC: btest-diff x509.log
# @TEST-EXEC: btest-diff known_certs.log

# @TEST-EXEC: zeek -r $TRACES/tls/google-duplicate.pcap %INPUT broker-store-config.zeek
# @TEST-EXEC: mv known_certs.log knowncerts-broker-store.log
# @TEST-EXEC: btest-diff knowncerts-broker-store.log

# @TEST-EXEC: zeek -r $TRACES/tls/google-duplicate.pcap %INPUT storage-framework-config.zeek
# @TEST-EXEC: mv known_certs.log knowncerts-storage-framework.log
# @TEST-EXEC: btest-diff knowncerts-storage-framework.log

# @TEST-EXEC: cat knowncerts-broker-store.log | $SCRIPTS/diff-remove-timestamps > broker-store.log
# @TEST-EXEC: cat knowncerts-storage-framework.log | $SCRIPTS/diff-remove-timestamps > storage-framework.log
# @TEST-EXEC: diff -u broker-store.log storage-framework.log

redef Cluster::default_store_dir = ".";

@load protocols/ssl/known-certs

redef Known::cert_tracking = ALL_HOSTS;

# @TEST-START-FILE broker-store-config.zeek

redef Known::use_cert_store=T;
redef Known::enable_certs_persistence=F;

# @TEST-END-FILE

# @TEST-START-FILE storage-framework-config.zeek

redef Known::use_cert_store=F;
redef Known::enable_certs_persistence=T;

# @TEST-END-FILE
