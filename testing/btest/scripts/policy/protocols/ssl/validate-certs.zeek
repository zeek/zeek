# Fedora/RedHat have SHA1 disabled for certificate verification, re-enable it for testing by setting OPENSSL_ENABLE_SHA1_SIGNATURES=1
#
# @TEST-EXEC: OPENSSL_ENABLE_SHA1_SIGNATURES=1 zeek -b -r $TRACES/tls/tls-expired-cert.trace $SCRIPTS/external-ca-list.zeek %INPUT
# @TEST-EXEC: cat ssl.log > ssl-all.log
# @TEST-EXEC: zeek -b -C -r $TRACES/tls/missing-intermediate.pcap $SCRIPTS/external-ca-list.zeek %INPUT
# @TEST-EXEC: cat ssl.log >> ssl-all.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-x509-names | $SCRIPTS/diff-remove-timestamps" btest-diff ssl-all.log

@load protocols/ssl/validate-certs
