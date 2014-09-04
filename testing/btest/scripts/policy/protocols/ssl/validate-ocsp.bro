# @TEST-EXEC: bro -C -r $TRACES/tls/ocsp-stapling.trace %INPUT
# @TEST-EXEC: btest-diff ssl.log
# @TEST-EXEC: bro -C -r $TRACES/tls/ocsp-stapling-twimg.trace %INPUT
# @TEST-EXEC: mv ssl.log ssl-twimg.log
# @TEST-EXEC: btest-diff ssl-twimg.log
# @TEST-EXEC: bro -C -r $TRACES/tls/ocsp-stapling-digicert.trace %INPUT
# @TEST-EXEC: mv ssl.log ssl-digicert.log
# @TEST-EXEC: btest-diff ssl-digicert.log

@load protocols/ssl/validate-ocsp
