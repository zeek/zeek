# A basic test of the known-hosts script's logging and asset_tracking options

# Don't run for C++ scripts because there's no script to compile.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"

# @TEST-EXEC: zeek -b -r $TRACES/wikipedia.pcap %INPUT Known::host_tracking=LOCAL_HOSTS
# @TEST-EXEC: mv known_hosts.log knownhosts-local.log
# @TEST-EXEC: btest-diff knownhosts-local.log

# @TEST-EXEC: zeek -b -r $TRACES/wikipedia.pcap %INPUT Known::host_tracking=REMOTE_HOSTS
# @TEST-EXEC: mv known_hosts.log knownhosts-remote.log
# @TEST-EXEC: btest-diff knownhosts-remote.log

# @TEST-EXEC: zeek -b -r $TRACES/wikipedia.pcap %INPUT Known::host_tracking=ALL_HOSTS
# @TEST-EXEC: mv known_hosts.log knownhosts-all.log
# @TEST-EXEC: btest-diff knownhosts-all.log

# @TEST-EXEC: zeek -b -r $TRACES/wikipedia.pcap %INPUT Known::host_tracking=NO_HOSTS
# @TEST-EXEC: test '!' -e known_hosts.log

# @TEST-EXEC: zeek -r $TRACES/wikipedia.pcap %INPUT broker-store-config.zeek
# @TEST-EXEC: mv known_hosts.log knownhosts-broker-store.log
# @TEST-EXEC: btest-diff knownhosts-broker-store.log

# @TEST-EXEC: zeek -r $TRACES/wikipedia.pcap %INPUT storage-framework-config.zeek
# @TEST-EXEC: mv known_hosts.log knownhosts-storage-framework.log
# @TEST-EXEC: btest-diff knownhosts-storage-framework.log

# @TEST-EXEC: cat knownhosts-broker-store.log | $SCRIPTS/diff-remove-timestamps > broker-store.log
# @TEST-EXEC: cat knownhosts-storage-framework.log | $SCRIPTS/diff-remove-timestamps > storage-framework.log
# @TEST-EXEC: diff broker-store.log storage-framework.log > logs-diff.txt
# @TEST-EXEC: btest-diff logs-diff.txt


@load protocols/conn/known-hosts

redef Site::local_nets += {141.142.0.0/16};

# @TEST-START-FILE broker-store-config.zeek

redef Known::use_host_store=T;
redef Known::enable_hosts_persistence=F;

# @TEST-END-FILE

# @TEST-START-FILE storage-framework-config.zeek

@load policy/frameworks/storage/backend/sqlite

redef Known::use_host_store=T;
redef Known::enable_hosts_persistence=T;

redef Known::host_store_backend_type = Storage::STORAGE_BACKEND_SQLITE;
redef Known::host_store_backend_options = [ $sqlite = [
    $database_path="test.sqlite", $table_name=Known::host_store_prefix ]];

# @TEST-END-FILE
