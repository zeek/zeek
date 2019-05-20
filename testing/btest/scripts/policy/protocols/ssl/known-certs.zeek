# @TEST-EXEC: zeek -r $TRACES/tls/google-duplicate.trace %INPUT
# @TEST-EXEC: btest-diff ssl.log
# @TEST-EXEC: btest-diff x509.log
# @TEST-EXEC: btest-diff known_certs.log

@load protocols/ssl/known-certs

redef Known::cert_tracking = ALL_HOSTS;

