
@load base/frameworks/files
@load base/files/hash

module X509;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	## The hash function used for certificate hashes. By default this is sha256; you can use
	## any other hash function and the hashes will change in ssl.log and in x509.log.
	option hash_function: function(cert: string): string = sha256_hash;

	## This option specifies if X.509 certificates are logged in file.log. Typically, there
	## is not much value to having the entry in files.log - especially since, by default, the
	## file ID is not present in the X509 log.
	option log_x509_in_files_log: bool = F;

	## The record type which contains the fields of the X.509 log.
	type Info: record {
		## Current timestamp.
		ts: time &log;
		## Fingerprint of the certificate - uses chosen algorithm.
		fp: string &log;
		## Basic information about the certificate.
		certificate: X509::Certificate &log;
		## The opaque wrapping the certificate. Mainly used
		## for the verify operations.
		handle: opaque of x509;
		## All extensions that were encountered in the certificate.
		extensions: vector of X509::Extension &default=vector();
		## Subject alternative name extension of the certificate.
		san: X509::SubjectAlternativeName &optional &log;
		## Basic constraints extension of the certificate.
		basic_constraints: X509::BasicConstraints &optional &log;
		## All extensions in the order they were raised.
		## This is used for caching certificates that are commonly
		## encountered and should not be relied on in user scripts.
		extensions_cache: vector of any &default=vector();
		## Indicates if this certificate was a end-host certificate, or sent as part of a chain
		host_cert: bool &log &default=F;
		## Indicates if this certificate was sent from the client
		client_cert: bool &log &default=F;
	};

	## This record is used to store information about the SCTs that are
	## encountered in Certificates.
	type SctInfo: record {
		## The version of the encountered SCT (should always be 0 for v1).
		version: count;
		## The ID of the log issuing this SCT.
		logid: string;
		## The timestamp at which this SCT was issued measured since the
		## epoch (January 1, 1970, 00:00), ignoring leap seconds, in
		## milliseconds. Not converted to a Zeek timestamp because we need
		## the exact value for validation.
		timestamp: count;
		## The hash algorithm used for this sct.
		hash_alg: count;
		## The signature algorithm used for this sct.
		sig_alg: count;
		## The signature of this SCT.
		signature: string;
	};

	## Event for accessing logged records.
	global log_x509: event(rec: Info);
}

redef record Files::Info += {
	## Information about X509 certificates. This is used to keep
	## certificate information until all events have been received.
	x509: X509::Info &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(X509::LOG, [$columns=Info, $ev=log_x509, $path="x509", $policy=log_policy]);

	# We use MIME types internally to distinguish between user and CA certificates.
	# The first certificate in a connection always gets tagged as user-cert, all
	# following certificates get tagged as CA certificates. Certificates gotten via
	# other means (e.g. identified from HTTP traffic when they are transfered in plain
	# text) get tagged as application/pkix-cert.
	Files::register_for_mime_type(Files::ANALYZER_X509, "application/x-x509-user-cert");
	Files::register_for_mime_type(Files::ANALYZER_X509, "application/x-x509-ca-cert");
	Files::register_for_mime_type(Files::ANALYZER_X509, "application/pkix-cert");

	# Always calculate hashes. They are not necessary for base scripts
	# but very useful for identification, and required for policy scripts
	Files::register_for_mime_type(Files::ANALYZER_MD5, "application/x-x509-user-cert");
	Files::register_for_mime_type(Files::ANALYZER_MD5, "application/x-x509-ca-cert");
	Files::register_for_mime_type(Files::ANALYZER_MD5, "application/pkix-cert");
	Files::register_for_mime_type(Files::ANALYZER_SHA1, "application/x-x509-user-cert");
	Files::register_for_mime_type(Files::ANALYZER_SHA1, "application/x-x509-ca-cert");
	Files::register_for_mime_type(Files::ANALYZER_SHA1, "application/pkix-cert");

	# SHA256 is used by us to determine which certificates to cache.
	Files::register_for_mime_type(Files::ANALYZER_SHA256, "application/x-x509-user-cert");
	Files::register_for_mime_type(Files::ANALYZER_SHA256, "application/x-x509-ca-cert");
	Files::register_for_mime_type(Files::ANALYZER_SHA256, "application/pkix-cert");
	}

hook Files::log_policy(rec: Files::Info, id: Log::ID, filter: Log::Filter) &priority=5
	{
	if ( ( log_x509_in_files_log == F ) && ( "X509" in rec$analyzers ) )
		break;
	}

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate) &priority=5
	{
	local der_cert = x509_get_certificate_string(cert_ref);
	local fp = hash_function(der_cert);
	f$info$x509 = [$ts=f$info$ts, $fp=fp, $certificate=cert, $handle=cert_ref];
	if ( f$info$mime_type == "application/x-x509-user-cert" )
		f$info$x509$host_cert = T;
	if ( f$is_orig )
		f$info$x509$client_cert = T;
	}

event x509_extension(f: fa_file, ext: X509::Extension) &priority=5
	{
	if ( f$info?$x509 )
		{
		f$info$x509$extensions += ext;
		f$info$x509$extensions_cache += ext;
		}
	}

event x509_ext_basic_constraints(f: fa_file, ext: X509::BasicConstraints) &priority=5
	{
	if ( f$info?$x509 )
		{
		f$info$x509$basic_constraints = ext;
		f$info$x509$extensions_cache += ext;
		}
	}

event x509_ext_subject_alternative_name(f: fa_file, ext: X509::SubjectAlternativeName) &priority=5
	{
	if ( f$info?$x509 )
		{
		f$info$x509$san = ext;
		f$info$x509$extensions_cache += ext;
		}
	}

event x509_ocsp_ext_signed_certificate_timestamp(f: fa_file, version: count, logid: string, timestamp: count, hash_algorithm: count, signature_algorithm: count, signature: string) &priority=5
	{
	if ( f$info?$x509 )
		f$info$x509$extensions_cache += SctInfo($version=version, $logid=logid, $timestamp=timestamp, $hash_alg=hash_algorithm, $sig_alg=signature_algorithm, $signature=signature);
	}

event file_state_remove(f: fa_file) &priority=5
	{
	if ( ! f$info?$x509 )
		return;

	Log::write(LOG, f$info$x509);
	}

