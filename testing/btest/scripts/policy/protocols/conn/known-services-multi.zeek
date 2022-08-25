# A test case for when more than a single service is detected for a given
# (addr, port) pair.

# @TEST-EXEC: zeek -b -C -r $TRACES/ssl-and-ssh-using-sslh.trace %INPUT "Known::service_tracking = ALL_HOSTS"
# @TEST-EXEC: btest-diff known_services.log

@load base/protocols/ssh
@load base/protocols/ssl
@load protocols/conn/known-services
