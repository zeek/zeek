# @TEST-EXEC: bro -C -r $TRACES/tls/ocsp-stapling.trace %INPUT
# @TEST-EXEC: btest-diff ssl.log

@load protocols/ssl/validate-ocsp
