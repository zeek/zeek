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

# @TEST-EXEC: zeek -r $TRACES/wikipedia.pcap %INPUT storage-framework-config.zeek
# @TEST-EXEC: mv known_hosts.log knownhosts-storage-framework.log
# @TEST-EXEC: btest-diff knownhosts-storage-framework.log

redef Cluster::default_store_dir = ".";

@load protocols/conn/known-hosts

redef Site::local_nets += {141.142.0.0/16};

# @TEST-START-FILE storage-framework-config.zeek

redef Known::enable_hosts_persistence=T;

# @TEST-END-FILE
