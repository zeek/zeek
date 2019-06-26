# @TEST-EXEC: zeek -r $TRACES/tls/signed_certificate_timestamp.pcap %INPUT
#
# The following file contains a tls 1.0 connection with a SCT in a TLS extension.
# This is interesting because the digitally-signed struct in TLS 1.0 does not come
# with a SignatureAndHashAlgorithm structure. The digitally-signed struct in the
# SCT is, however, based on the TLS 1.2 RFC, no matter which version of TLS one
# uses in the end. So this one does have a Signature/Hash alg, even if the protocol
# itself does not carry it in the same struct.
#
# @TEST-EXEC: zeek -r $TRACES/tls/signed_certificate_timestamp_tls1_0.pcap %INPUT
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: test ! -f dpd.log

export {
	type LogInfo: record {
		version: count;
		logid: string;
		timestamp: count;
		sig_alg: count;
		hash_alg: count;
		signature: string;
	};
}

redef record SSL::Info += {
	ct_proofs: vector of LogInfo &default=vector();
};

event ssl_extension_signed_certificate_timestamp(c: connection, is_orig: bool, version: count, logid: string, timestamp: count, signature_and_hashalgorithm: SSL::SignatureAndHashAlgorithm, signature: string)
	{
	print version, SSL::ct_logs[logid]$description, double_to_time(timestamp/1000.0), signature_and_hashalgorithm;
	c$ssl$ct_proofs[|c$ssl$ct_proofs|] = LogInfo($version=version, $logid=logid, $timestamp=timestamp, $sig_alg=signature_and_hashalgorithm$SignatureAlgorithm, $hash_alg=signature_and_hashalgorithm$HashAlgorithm, $signature=signature);
	}

event ssl_established(c: connection)
	{
	if ( ! c$ssl?$cert_chain || |c$ssl$cert_chain| == 0 || ! c$ssl$cert_chain[0]?$x509 )
		return;

	local cert = c$ssl$cert_chain[0]$x509$handle;

	for ( i in c$ssl$ct_proofs )
		{
		local log = c$ssl$ct_proofs[i];

		print "Verify of", SSL::ct_logs[log$logid]$description, sct_verify(cert, log$logid, SSL::ct_logs[log$logid]$key, log$signature, log$timestamp, log$hash_alg);
		print "Bad verify of", SSL::ct_logs[log$logid]$description, sct_verify(cert, log$logid, SSL::ct_logs[log$logid]$key, log$signature, log$timestamp+1, log$hash_alg);
		}
	}
