# @TEST-EXEC: zeek -b -r $TRACES/tls/tls1.2.trace %INPUT
# This is a hack to get around the fact that the output format changed between OpenSSL 1.1 and OpenSS:
# 3.0.
# @TEST-EXEC: cp .stdout stdout-openssl-3.0
# @TEST-EXEC: grep -q "^ZEEK_HAVE_OPENSSL_3_0.*true" $BUILD/CMakeCache.txt && btest-diff stdout-openssl-3.0 || btest-diff .stdout

@load base/protocols/ssl
@load base/files/x509

event x509_extension(f: fa_file, extension: X509::Extension)
{
	# The formatting of CRL Distribution Points varies between OpenSSL versions. Skip it
	# for the test.
	if ( extension$short_name != "crlDistributionPoints" ) 
		print extension;
}
