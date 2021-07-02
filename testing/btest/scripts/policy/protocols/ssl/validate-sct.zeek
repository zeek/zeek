# @TEST-EXEC: zeek -b -r $TRACES/tls/signed_certificate_timestamp.pcap $SCRIPTS/external-ca-list.zeek %INPUT
# @TEST-EXEC: cat ssl.log > ssl-all.log
# @TEST-EXEC: zeek -b -r $TRACES/tls/signed_certificate_timestamp-2.pcap $SCRIPTS/external-ca-list.zeek %INPUT
# @TEST-EXEC: cat ssl.log >> ssl-all.log
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-x509-names | $SCRIPTS/diff-remove-timestamps" btest-diff ssl-all.log

@load protocols/ssl/validate-sct

redef SSL::ct_logs += {
["\x03\x01\x9d\xf3\xfd\x85\xa6\x9a\x8e\xbd\x1f\xac\xc6\xda\x9b\xa7\x3e\x46\x97\x74\xfe\x77\xf5\x79\xfc\x5a\x08\xb8\x32\x8c\x1d\x6b"] = SSL::CTInfo($description="Venafi Gen2 CT log", $operator="Venafi", $url="ctlog-gen2.api.venafi.com/", $maximum_merge_delay=86400, $key="\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00\x04\x8e\x27\x27\x7a\xb6\x55\x09\x74\xeb\x6c\x4b\x94\x84\x65\xbc\xe4\x15\xf1\xea\x5a\xd8\x7c\x0e\x37\xce\xba\x3f\x6c\x09\xda\xe7\x29\x96\xd3\x45\x50\x6f\xde\x1e\xb4\x1c\xd2\x83\x88\xff\x29\x2f\xce\xa9\xff\xdf\x34\xde\x75\x0f\xc0\xcc\x18\x0d\x94\x2e\xfc\x37\x01"),
};

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
