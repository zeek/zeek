# @TEST-DOC: A basic test of the known-services script's logging and asset_tracking options

# Don't run for C++ scripts because there's no script to compile.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"

# @TEST-EXEC: zeek -r $TRACES/var-services-std-ports.trace %INPUT Known::service_tracking=LOCAL_HOSTS
# @TEST-EXEC: mv known_services.log knownservices-local.log
# @TEST-EXEC: btest-diff knownservices-local.log

# @TEST-EXEC: zeek -r $TRACES/var-services-std-ports.trace %INPUT Known::service_tracking=REMOTE_HOSTS
# @TEST-EXEC: mv known_services.log knownservices-remote.log
# @TEST-EXEC: btest-diff knownservices-remote.log

# @TEST-EXEC: zeek -r $TRACES/var-services-std-ports.trace %INPUT Known::service_tracking=ALL_HOSTS
# @TEST-EXEC: mv known_services.log knownservices-all.log
# @TEST-EXEC: btest-diff knownservices-all.log

# @TEST-EXEC: zeek -r $TRACES/var-services-std-ports.trace %INPUT Known::service_tracking=NO_HOSTS
# @TEST-EXEC: test '!' -e known_services.log

# @TEST-EXEC: zeek -r $TRACES/var-services-std-ports.trace %INPUT broker-store-config.zeek
# @TEST-EXEC: mv known_services.log knownservices-broker-store.log
# @TEST-EXEC: btest-diff knownservices-broker-store.log

# @TEST-EXEC: zeek -r $TRACES/var-services-std-ports.trace %INPUT storage-framework-config.zeek
# @TEST-EXEC: mv known_services.log knownservices-storage-framework.log
# @TEST-EXEC: btest-diff knownservices-storage-framework.log

# @TEST-EXEC: cat knownservices-broker-store.log | $SCRIPTS/diff-remove-timestamps > broker-store.log
# @TEST-EXEC: cat knownservices-storage-framework.log | $SCRIPTS/diff-remove-timestamps > storage-framework.log
# @TEST-EXEC: diff broker-store.log storage-framework.log > logs-diff.txt
# @TEST-EXEC: btest-diff logs-diff.txt

@load protocols/conn/known-services

redef Site::local_nets += {172.16.238.0/24};

# @TEST-START-FILE broker-store-config.zeek

redef Known::service_tracking=ALL_HOSTS;
redef Known::use_service_store=T;
redef Known::use_storage_framework=F;

# @TEST-END-FILE

# @TEST-START-FILE storage-framework-config.zeek

@load policy/frameworks/storage/backend/sqlite

redef Known::service_tracking=ALL_HOSTS;
redef Known::use_service_store=T;
redef Known::use_storage_framework=T;

redef Known::service_store_backend_type = Storage::STORAGE_BACKEND_SQLITE;
redef Known::service_store_backend_options = [ $sqlite = [
    $database_path="test.sqlite", $table_name=Known::service_store_prefix ]];

# @TEST-END-FILE
