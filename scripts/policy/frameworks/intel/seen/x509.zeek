@load base/frameworks/intel
@load base/files/x509
@load ./where-locations

module Intel;

export {
        ## Enables the extraction of subject alternate names from the X509 SAN DNS field
        option enable_x509_ext_subject_alternative_name = T;
}

event x509_ext_subject_alternative_name(f: fa_file, ext: X509::SubjectAlternativeName)
	{
	if ( enable_x509_ext_subject_alternative_name && ext?$dns )
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

	if ( f$info?$sha1 ) # if the file_hash event was raised before the x509 event...
		{
		Intel::seen([$indicator=f$info$sha1,
		             $indicator_type=Intel::CERT_HASH,
		             $f=f,
		             $where=X509::IN_CERT]);
		}
	}

event file_hash(f: fa_file, kind: string, hash: string)
	{
	if ( ! f?$info || ! f$info?$x509 || kind != "sha1" )
		return;

	Intel::seen([$indicator=hash,
	             $indicator_type=Intel::CERT_HASH,
	             $f=f,
	             $where=X509::IN_CERT]);
	}
