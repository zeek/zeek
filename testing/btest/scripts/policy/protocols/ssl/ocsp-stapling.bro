# This tests logging of ocsp stapling message

# @TEST-EXEC: bro -C -r $TRACES/tls/ocsp-stapling.trace %INPUT
# @TEST-EXEC: btest-diff ocsp-stapling.log

@load protocols/ssl/ocsp-stapling
