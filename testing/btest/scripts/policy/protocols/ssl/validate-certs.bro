# @TEST-EXEC: bro -r $TRACES/tls/tls-expired-cert.trace %INPUT
# @TEST-EXEC: btest-diff ssl.log

@load protocols/ssl/validate-certs
