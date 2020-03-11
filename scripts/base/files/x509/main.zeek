@load base/frameworks/files
@load base/files/hash

module X509;

export {
	redef enum Log::ID += { LOG };

	## How often do you have to encounter a certificate before
	## caching it. Set to 0 to disable caching of certificates.
	option caching_required_encounters : count = 10;

	## The timespan over which caching_required_encounters has to be reached
	option caching_required_encounters_interval : interval = 1 mins;

	## After a certificate has not been encountered for this time, it
	## may be evicted from the certificate cache.
	option certificate_cache_minimum_eviction_interval : interval = 1 mins;

	## Maximum size of the certificate cache
	option certificate_cache_max_entries : count = 10000;

	## The record type which contains the fields of the X.509 log.
	type Info: record {
		## Current timestamp.
		ts: time &log;
		## File id of this certificate.
		id: string &log;
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

	## This hook performs event-replays in case a certificate that already
	## is in the cache is encountered.
	##
	## It is possible to change this behavior/skip sending the events by
	## installing a higher priority hook instead.
	global x509_certificate_cache_replay: hook(f: fa_file, sha256: string);

	## Event for accessing logged records.
	global log_x509: event(rec: Info);
}

# Table tracking potential certificates to cache - indexed by the SHA256 of the
# raw on-the-wire representation (DER).
global certificates_encountered: table[string] of count &create_expire=caching_required_encounters_interval;

# Table caching the output of the X509 analyzer for commonly seen certificates.
# This is indexed by SHA256 and contains the Info record of the first certificate
# encountered. We use this info record to re-play the events.
global certificate_cache: table[string] of X509::Info &read_expire=certificate_cache_minimum_eviction_interval;

redef record Files::Info += {
	## Information about X509 certificates. This is used to keep
	## certificate information until all events have been received.
	x509: X509::Info &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(X509::LOG, [$columns=Info, $ev=log_x509, $path="x509"]);

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

	x509_set_certificate_cache(certificate_cache);
	x509_set_certificate_cache_hit_callback(x509_certificate_cache_replay);
	}

hook x509_certificate_cache_replay(f: fa_file, sha256: string)
	{
	# we encountered a cached cert. The X509 analyzer will skip it. Let's raise all the events that it typically
	# raises by ourselfes.

	# first - let's checked if it already has an x509 record. That would mean that someone raised the file_hash event
	# several times for the certificate - in which case we bail out.
	if ( f$info?$x509 )
		return;

	local e = certificate_cache[sha256];
	event x509_certificate(f, e$handle, e$certificate);
	for ( i in e$extensions_cache )
		{
		local ext = e$extensions_cache[i];

		if ( ext is X509::Extension )
			event x509_extension(f, (ext as X509::Extension));
		else if ( ext is X509::BasicConstraints )
			event x509_ext_basic_constraints(f, (ext as X509::BasicConstraints));
		else if ( ext is X509::SubjectAlternativeName )
			event x509_ext_subject_alternative_name(f, (ext as X509::SubjectAlternativeName));
		else if ( ext is X509::SctInfo )
			{
			local s = ( ext as X509::SctInfo);
			event x509_ocsp_ext_signed_certificate_timestamp(f, s$version, s$logid, s$timestamp, s$hash_alg, s$sig_alg, s$signature);
			}
		else
			Reporter::error(fmt("Encountered unknown extension while replaying certificate with fuid %s", f$id)); 
		}
	}

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate) &priority=5
	{
	f$info$x509 = [$ts=f$info$ts, $id=f$id, $certificate=cert, $handle=cert_ref];
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

	if ( f$info?$sha256 && f$info$sha256 !in certificate_cache &&
		caching_required_encounters > 0 &&
		f$info$sha256 in certificates_encountered &&
		certificates_encountered[f$info$sha256] >= caching_required_encounters &&
		|certificate_cache| < certificate_cache_max_entries )
		{
		delete certificates_encountered[f$info$sha256];
		certificate_cache[f$info$sha256] = f$info$x509;
		}

	}

event file_hash(f: fa_file, kind: string, hash: string)
	{
	if ( ! f?$info || "X509" !in f$info$analyzers || kind != "sha256" )
		return;

	if ( caching_required_encounters == 0 )
		return;

	if ( hash !in certificates_encountered )
		certificates_encountered[hash] = 0;

	certificates_encountered[hash] += 1;

	if ( certificates_encountered[hash] < caching_required_encounters )
		return;
	}
