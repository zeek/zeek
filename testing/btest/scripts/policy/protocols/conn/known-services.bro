# A basic test of the known-services script's logging and asset_tracking options

# @TEST-EXEC: bro -r $TRACES/var-services-std-ports.trace %INPUT Known::service_tracking=LOCAL_HOSTS
# @TEST-EXEC: mv known_services.log knownservices-local.log
# @TEST-EXEC: btest-diff knownservices-local.log

# @TEST-EXEC: bro -r $TRACES/var-services-std-ports.trace %INPUT Known::service_tracking=REMOTE_HOSTS
# @TEST-EXEC: mv known_services.log knownservices-remote.log
# @TEST-EXEC: btest-diff knownservices-remote.log

# @TEST-EXEC: bro -r $TRACES/var-services-std-ports.trace %INPUT Known::service_tracking=ALL_HOSTS
# @TEST-EXEC: mv known_services.log knownservices-all.log
# @TEST-EXEC: btest-diff knownservices-all.log

# @TEST-EXEC: bro -r $TRACES/var-services-std-ports.trace %INPUT Known::service_tracking=NO_HOSTS
# @TEST-EXEC: test '!' -e known_services.log

# @TEST-EXEC: bro -r $TRACES/ssl-and-ssh-using-sslh.trace %INPUT Known::service_tracking=ALL_HOSTS
# @TEST-EXEC: mv known_services.log knownservices-sslh.log
# @TEST-EXEC: btest-diff knownservices-sslh.log

# @TEST-EXEC: bro -r $TRACES/globus-url-copy.trace %INPUT Known::service_tracking=ALL_HOSTS GridFTP::size_threshold=1
# @TEST-EXEC: mv known_services.log knownservices-gridftp.log
# @TEST-EXEC: btest-diff knownservices-gridftp.log

# @TEST-EXEC: bro -r $TRACES/ssl-and-ssh-using-sslh.trace %INPUT Known::service_tracking=ALL_HOSTS
# @TEST-EXEC: mv known_services.log knownservices-sslh.log
# @TEST-EXEC: btest-diff knownservices-sslh.log

@load protocols/conn/known-services

redef Site::local_nets += {172.16.238.0/24};
