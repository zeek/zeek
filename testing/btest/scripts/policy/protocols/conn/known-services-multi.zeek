# A test case for when more than a single service is detected for a given
# (addr, port) pair.

# @TEST-EXEC: zeek -C -r $TRACES/ssl-and-ssh-using-sslh.trace %INPUT "Known::service_tracking = ALL_HOSTS"
# @TEST-EXEC: btest-diff known_services.log

@load protocols/conn/known-services
