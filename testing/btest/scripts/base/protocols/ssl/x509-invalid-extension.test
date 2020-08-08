# @TEST-EXEC: zeek -b -C -r $TRACES/tls/ocsp-stapling.trace %INPUT
# @TEST-EXEC: btest-diff .stdout

@load base/protocols/ssl

event x509_extension(f: fa_file, ext: X509::Extension)
	{
	if ( ext$oid != "1.3.6.1.5.5.7.1.12" )
		return;

	print ext$short_name;
	print ext$value;
	}
