##! This script sets up the certificate event cache handling of Zeek.
##!
##! The Zeek core provided a method to skip certificate processing for known certificates.
##! For more details about this functionality, see :zeek:see:`x509_set_certificate_cache`.
##!
##! This script uses this feature to lower the amount of processing that has to be performed
##! by Zeek by caching all certificate events for common certificates. For these certificates,
##! the parsing of certificate information in the core is disabled. Instead, the cached events
##! and data structures from the previous certificates are used.

@load ./main

module X509;

export {
	## How often do you have to encounter a certificate before
	## caching the events for it. Set to 0 to disable caching of certificates.
	option caching_required_encounters : count = 10;

	## The timespan over which caching_required_encounters has to be reached
	option caching_required_encounters_interval : interval = 62 secs;

	## After a certificate has not been encountered for this time, it
	## may be evicted from the certificate event cache.
	option certificate_cache_minimum_eviction_interval : interval = 62 secs;

	## Maximum size of the certificate event cache
	option certificate_cache_max_entries : count = 10000;

	## This hook performs event-replays in case a certificate that already
	## is in the cache is encountered.
	##
	## It is possible to change this behavior/skip sending the events by
	## installing a higher priority hook instead.
	global x509_certificate_cache_replay: hook(f: fa_file, e: X509::Info, sha256: string);
}

# Table tracking potential certificates to cache - indexed by the SHA256 of the
# raw on-the-wire representation (DER).
global certificates_encountered: table[string] of count &create_expire=caching_required_encounters_interval;

# Table caching the output of the X509 analyzer for commonly seen certificates.
# This is indexed by SHA256 and contains the Info record of the first certificate
# encountered. We use this info record to re-play the events.
global certificate_cache: table[string] of X509::Info &read_expire=certificate_cache_minimum_eviction_interval;

event zeek_init() &priority=5
	{
	x509_set_certificate_cache(certificate_cache);
	x509_set_certificate_cache_hit_callback(x509_certificate_cache_replay);
	}

hook x509_certificate_cache_replay(f: fa_file, e: X509::Info, sha256: string)
	{
	# we encountered a cached cert. The X509 analyzer will skip it. Let's raise all the events that it typically
	# raises by ourselves.

	# first - let's checked if it already has an x509 record. That would mean that someone raised the file_hash event
	# several times for the certificate - in which case we bail out.
	if ( f$info?$x509 )
		return;

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

event file_state_remove(f: fa_file) &priority=5
	{
	if ( ! f$info?$x509 )
		return;

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

	if ( caching_required_encounters == 0 || hash in certificate_cache )
		return;

	if ( hash !in certificates_encountered )
		certificates_encountered[hash] = 1;
	else
		certificates_encountered[hash] += 1;
	}
