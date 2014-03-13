@load base/frameworks/files
@load base/files/hash

module X509;

export {
	redef enum Log::ID += { LOG };

	## Set that keeps track of the certificates which were logged recently.
	global cert_hashes: set[string] &create_expire=1hrs &synchronized &redef;

	type Info: record {
		## current timestamp
		ts: time &log;

		## SHA-1 hash of this certificate
		sha1: string &log &optional;
    
		## Basic information about the certificate
		certificate: X509::Certificate &log;

		## The opaque wrapping the certificate. Mainly used
		## for the verify operations
		handle: opaque of x509;

		## All extensions that were encountered in the certificate
		extensions: vector of X509::Extension &default=vector();

		## Subject alternative name extension of the certificate
		san: X509::SubjectAlternativeName &optional &log;

		## Basic constraints extension of the certificate
		basic_constraints: X509::BasicConstraints &optional &log;
	};

	## Event for accessing logged records.
	global log_x509: event(rec: Info);
}

event bro_init() &priority=5
	{
	Log::create_stream(X509::LOG, [$columns=Info, $ev=log_x509]);
	}

redef record Files::Info += {
	## Information about X509 certificates. This is used to keep
	## certificate information until all events have been received.
	x509: X509::Info &optional;
};

# Either, this event arrives first - then info$x509 does not exist 
# yet and this is a no-op, and the sha1 value is set in x509_certificate.
# Or the x509_certificate event arrives first - then the hash is set here.
event file_hash(f: fa_file, kind: string, hash: string)
	{
	if ( f$info?$x509 && kind == "sha1" )
		f$info$x509$sha1 = hash;
	}

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate) &priority=5
	{
	f$info$x509 = [$ts=f$info$ts, $certificate=cert, $handle=cert_ref];
	if ( f$info?$sha1 )
		f$info$x509$sha1 = f$info$sha1;
	}

event x509_extension(f: fa_file, ext: X509::Extension) &priority=5
	{
	if ( f$info?$x509 )
		f$info$x509$extensions[|f$info$x509$extensions|] = ext;
	}

event x509_ext_basic_constraints(f: fa_file, ext: X509::BasicConstraints) &priority=5
	{
	if ( f$info?$x509 )
		f$info$x509$basic_constraints = ext;
	}

event x509_ext_subject_alternative_name(f: fa_file, ext: X509::SubjectAlternativeName) &priority=5
	{
	if ( f$info?$x509 )
		f$info$x509$san = ext;
	}

event file_state_remove(f: fa_file) &priority=5
	{
	if ( ! f$info?$x509 )
		return;

	if ( ! f$info$x509?$sha1 )
		{
		Reporter::error(fmt("Certificate without a hash value. Logging skipped. File-id: %s", f$id));
		return;
		}

	if ( f$info$x509$sha1 in cert_hashes )
		# we already have seen & logged this certificate
		return;

	add cert_hashes[f$info$x509$sha1];

	Log::write(LOG, f$info$x509);
	}
