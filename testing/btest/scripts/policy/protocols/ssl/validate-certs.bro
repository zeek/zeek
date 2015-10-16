# @TEST-EXEC: bro -r $TRACES/tls/tls-expired-cert.trace $SCRIPTS/external-ca-list.bro %INPUT
# @TEST-EXEC: cat ssl.log > ssl-all.log
# @TEST-EXEC: bro -C -r $TRACES/tls/missing-intermediate.pcap $SCRIPTS/external-ca-list.bro %INPUT
# @TEST-EXEC: cat ssl.log >> ssl-all.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-x509-names | $SCRIPTS/diff-remove-timestamps" btest-diff ssl-all.log

@load protocols/ssl/validate-certs.bro
