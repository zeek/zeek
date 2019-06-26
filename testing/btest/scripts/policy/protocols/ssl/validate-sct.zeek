# @TEST-EXEC: zeek -r $TRACES/tls/signed_certificate_timestamp.pcap $SCRIPTS/external-ca-list.zeek %INPUT
# @TEST-EXEC: cat ssl.log > ssl-all.log
# @TEST-EXEC: zeek -r $TRACES/tls/signed_certificate_timestamp-2.pcap $SCRIPTS/external-ca-list.zeek %INPUT
# @TEST-EXEC: cat ssl.log >> ssl-all.log
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-x509-names | $SCRIPTS/diff-remove-timestamps" btest-diff ssl-all.log

@load protocols/ssl/validate-sct

module SSL;

event ssl_established(c: connection)
	{
	print c$ssl$ct_proofs;
	for ( i in c$ssl$ct_proofs )
		{
		local proof = c$ssl$ct_proofs[i];
		local log = SSL::ct_logs[proof$logid];
		print log$description, proof$valid;
		}
	}
