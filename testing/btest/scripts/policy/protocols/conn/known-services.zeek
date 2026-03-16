# @TEST-REQUIRES: grep -q "#define HAVE_BROKER" $BUILD/zeek-config.h
# @TEST-DOC: A basic test of the known-services script's logging and asset_tracking options

# Don't run for C++ scripts because there's no script to compile.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"

# @TEST-EXEC: zeek -r $TRACES/var-services-std-ports.pcap %INPUT Known::service_tracking=LOCAL_HOSTS
# @TEST-EXEC: mv known_services.log knownservices-local.log
# @TEST-EXEC: btest-diff knownservices-local.log

# @TEST-EXEC: zeek -r $TRACES/var-services-std-ports.pcap %INPUT Known::service_tracking=REMOTE_HOSTS
# @TEST-EXEC: mv known_services.log knownservices-remote.log
# @TEST-EXEC: btest-diff knownservices-remote.log

# @TEST-EXEC: zeek -r $TRACES/var-services-std-ports.pcap %INPUT Known::service_tracking=ALL_HOSTS
# @TEST-EXEC: mv known_services.log knownservices-all.log
# @TEST-EXEC: btest-diff knownservices-all.log

# @TEST-EXEC: zeek -r $TRACES/var-services-std-ports.pcap %INPUT Known::service_tracking=NO_HOSTS
# @TEST-EXEC: test '!' -e known_services.log

# @TEST-EXEC: zeek -r $TRACES/var-services-std-ports.pcap %INPUT broker-store-config.zeek
# @TEST-EXEC: mv known_services.log knownservices-broker-store.log
# @TEST-EXEC: btest-diff knownservices-broker-store.log

# @TEST-EXEC: zeek -r $TRACES/var-services-std-ports.pcap %INPUT storage-framework-config.zeek
# @TEST-EXEC: mv known_services.log knownservices-storage-framework.log
# @TEST-EXEC: btest-diff knownservices-storage-framework.log

# @TEST-EXEC: cat knownservices-broker-store.log | $SCRIPTS/diff-remove-timestamps > broker-store.log
# @TEST-EXEC: cat knownservices-storage-framework.log | $SCRIPTS/diff-remove-timestamps > storage-framework.log
# @TEST-EXEC: diff -u broker-store.log storage-framework.log

redef Cluster::default_store_dir = ".";

@load protocols/conn/known-services

redef Site::local_nets += {172.16.238.0/24};

# @TEST-START-FILE broker-store-config.zeek

redef Known::service_tracking=ALL_HOSTS;
redef Known::use_service_store=T;
redef Known::enable_services_persistence=F;

# @TEST-END-FILE

# @TEST-START-FILE storage-framework-config.zeek

redef Known::service_tracking=ALL_HOSTS;
redef Known::use_service_store=F;
redef Known::enable_services_persistence=T;

# @TEST-END-FILE
