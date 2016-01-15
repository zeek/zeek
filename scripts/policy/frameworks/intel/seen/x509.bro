@load base/frameworks/intel
@load base/files/x509
@load ./where-locations

event x509_ext_subject_alternative_name(f: fa_file, ext: X509::SubjectAlternativeName)
	{
	if ( ext?$dns )
		{
		for ( i in ext$dns )
			Intel::seen([$indicator=ext$dns[i],
				$indicator_type=Intel::DOMAIN,
				$f=f,
				$where=X509::IN_CERT]);
		}
	}

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate)
	{
	if ( /emailAddress=/ in cert$subject )
		{
		local email = sub(cert$subject, /^.*emailAddress=/, "");
		email = sub(email, /,.*$/, "");
		Intel::seen([$indicator=email,
			     $indicator_type=Intel::EMAIL,
			     $f=f,
			     $where=X509::IN_CERT]);
		}
	}
