# This tests the certificate_request message parsing

# @TEST-EXEC: zeek -b -r $TRACES/tls/client-certificate.pcap %INPUT > out
# @TEST-EXEC: zeek -C -b -r $TRACES/tls/certificate-request-failed.pcap %INPUT >> out
# @TEST-EXEC: zeek -C -b -r $TRACES/tls/webrtc-stun.pcap %INPUT >> out
# @TEST-EXEC: zeek -C -b -r $TRACES/mysql/encrypted.trace %INPUT >> out
# @TEST-EXEC: btest-diff out

@load base/protocols/ssl
@load base/protocols/mysql

event ssl_certificate_request(c: connection, is_client: bool, certificate_types: index_vec, supported_signature_algorithms: SSL::SignatureAndHashAlgorithm, certificate_authorities: string_vec)
	{
	print certificate_types;
	print supported_signature_algorithms;
	for ( i in certificate_authorities )
		{
		print certificate_authorities[i];
		print parse_distinguished_name(certificate_authorities[i]);
		}
	print "========";
	}
