# @TEST-EXEC: bro -r $TRACES/tls/tls-expired-cert.trace %INPUT
# @TEST-EXEC: cat ssl.log > ssl-all.log
# @TEST-EXEC: bro -C -r $TRACES/tls/missing-intermediate.pcap %INPUT
# @TEST-EXEC: cat ssl.log >> ssl-all.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-x509-names btest-diff ssl-all.log

@load protocols/ssl/validate-certs.bro
