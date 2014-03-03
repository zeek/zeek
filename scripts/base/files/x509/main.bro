
@load base/frameworks/files

module X509;

export {
	redef enum Log::ID += { LOG };

	redef record Files::Info += {
	};
}

event x509_cert(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate)
	{
	print cert;
	}

event x509_extension(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate, ext: X509::Extension)
{
print ext;
}

event x509_ext_basic_constraints(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate, ext: X509::BasicConstraints)
{
print ext;
}

event x509_ext_subject_alternative_name(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate, ext: string_vec) 
{
print ext;
}

