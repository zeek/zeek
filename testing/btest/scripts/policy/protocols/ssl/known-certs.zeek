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
# @TEST-EXEC: diff broker-store.log storage-framework.log > logs-diff.txt
# @TEST-EXEC: btest-diff logs-diff.txt

@load protocols/ssl/known-certs

redef Known::cert_tracking = ALL_HOSTS;

# @TEST-START-FILE broker-store-config.zeek

redef Known::use_cert_store=T;
redef Known::enable_certs_persistence=F;

# @TEST-END-FILE

# @TEST-START-FILE storage-framework-config.zeek

@load policy/frameworks/storage/backend/sqlite

redef Known::use_cert_store=T;
redef Known::enable_certs_persistence=T;

redef Known::cert_store_backend_type = Storage::STORAGE_BACKEND_SQLITE;
redef Known::cert_store_backend_options = [ $sqlite = [
    $database_path="test.sqlite", $table_name=Known::cert_store_prefix ]];

# @TEST-END-FILE
