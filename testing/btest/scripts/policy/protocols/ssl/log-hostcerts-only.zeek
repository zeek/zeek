# @TEST-EXEC: bro -r $TRACES/tls/google-duplicate.trace %INPUT
# @TEST-EXEC: btest-diff x509.log

@load protocols/ssl/log-hostcerts-only
