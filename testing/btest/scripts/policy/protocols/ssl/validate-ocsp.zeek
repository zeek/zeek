# Fedora/RedHat have SHA1 disabled for certificate verification, re-enable it for testing by setting OPENSSL_ENABLE_SHA1_SIGNATURES=1
#
# @TEST-EXEC: OPENSSL_ENABLE_SHA1_SIGNATURES=1 zeek -b $SCRIPTS/external-ca-list.zeek -C -r $TRACES/tls/ocsp-stapling.trace %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-x509-names | $SCRIPTS/diff-remove-timestamps" btest-diff ssl.log
# @TEST-EXEC: OPENSSL_ENABLE_SHA1_SIGNATURES=1 zeek -b $SCRIPTS/external-ca-list.zeek -C -r $TRACES/tls/ocsp-stapling-twimg.trace %INPUT
# @TEST-EXEC: mv ssl.log ssl-twimg.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-x509-names | $SCRIPTS/diff-remove-timestamps" btest-diff ssl-twimg.log
# @TEST-EXEC: zeek -b $SCRIPTS/external-ca-list.zeek -C -r $TRACES/tls/ocsp-stapling-digicert.trace %INPUT
# @TEST-EXEC: mv ssl.log ssl-digicert.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-x509-names | $SCRIPTS/diff-remove-timestamps" btest-diff ssl-digicert.log

@load protocols/ssl/validate-ocsp
