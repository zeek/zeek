# A basic test of the known-services script's logging and asset_tracking options

# @TEST-EXEC: bro -r $TRACES/var-services-std-ports.trace %INPUT KnownServices::asset_tracking=LOCAL_HOSTS
# @TEST-EXEC: mv knownservices.log knownservices-local.log
# @TEST-EXEC: btest-diff knownservices-local.log

# @TEST-EXEC: bro -r $TRACES/var-services-std-ports.trace %INPUT KnownServices::asset_tracking=REMOTE_HOSTS
# @TEST-EXEC: mv knownservices.log knownservices-remote.log
# @TEST-EXEC: btest-diff knownservices-remote.log

# @TEST-EXEC: bro -r $TRACES/var-services-std-ports.trace %INPUT KnownServices::asset_tracking=ALL_HOSTS
# @TEST-EXEC: mv knownservices.log knownservices-all.log
# @TEST-EXEC: btest-diff knownservices-all.log

# @TEST-EXEC: bro -r $TRACES/var-services-std-ports.trace %INPUT KnownServices::asset_tracking=NO_HOSTS
# @TEST-EXEC: test '!' -e knownservices.log

@load conn/known-services
@load http
@load ssh
@load ftp

redef local_nets += {172.16.238.0/24};
