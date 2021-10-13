# @TEST-EXEC: zeek -b -r $TRACES/tls/google-duplicate.trace %INPUT
# @TEST-EXEC: btest-diff x509.log

@load protocols/ssl/log-hostcerts-only

redef X509::relog_known_certificates_after = 0secs;
