##! This script disables repeat certificate events for hosts for hosts for which the same
##! certificate was seen in the recent past;
##!
##! This script specifically plugs into the event caching mechanism that is set up by the
##! base X509 script certificate-event-cache.zeek. It adds another layer of tracking that
##! checks if the same certificate was seen for the server IP address before, when the same
##! SNI was used to connect. If the certificate is in the event cache and all of these conditions
##! apply, then no certificate related events will be raised.
##!
##! Please note that while this optimization can lead to a considerable reduction of load in some
##! settings, it also means that certain detection scripts that rely on the certificate events being
##! raised do no longer work - since the events will not be raised for all connections.
##!
##! Currently this script only works for X509 certificates that are sent via SSL/TLS connections.
##!
##! If you use any script that requires certificate events for each single connection,
##! you should not load this script.

@load base/protocols/ssl
@load base/files/x509

module DisableX509Events;

## Let's be a bit more generous with the number of certificates that we allow to be put into
## the cache.
redef X509::certificate_cache_max_entries = 100000;

type CacheIndex: record {
	## IP address of the server the certificate was seen on.
	ip: addr;
	## SNI the client sent in the connection
	sni: string &optional;
	## sha256 of the certificate
	sha256: string;
};

redef record SSL::Info += {
	## Set to true to force certificate events to always be raised for this connection.
	always_raise_x509_events: bool &default=F;
};

redef record X509::Info += {
	## Set to true to force certificate events to always be raised for this certificate.
	always_raise_x509_events: bool &default=F;
};

global certificate_replay_tracking: set[CacheIndex] &read_expire=X509::certificate_cache_minimum_eviction_interval;

hook X509::x509_certificate_cache_replay(f: fa_file, e: X509::Info, sha256: string) &priority=5
	{
	# Bail out if x509 is already set - or if the file tells us that we should always raise events.
	if ( f$info?$x509 || e$always_raise_x509_events )
		return;

	local raise_events = F;

	# not sure how that could happen - but let's be safe...
	if ( |f$conns| == 0 )
		return;

	for ( c in f$conns )
		{
		if ( ! f$conns[c]?$ssl )
			return;

		local test = CacheIndex($ip=f$conns[c]$id$resp_h, $sha256=sha256);
		if ( f$conns[c]$ssl?$server_name )
			test$sni = f$conns[c]$ssl$server_name;

		if ( test !in certificate_replay_tracking || f$conns[c]$ssl$always_raise_x509_events )
			{
			raise_events = T;
			add certificate_replay_tracking[test];
			}
		}

	if ( ! raise_events )
		{
		# We don't have to raise the events. :).
		# Instead we just already set f$x509. That makes the data available to scripts that might need them - and the x509_certificate_cache_replayh
		# hook in certificate-event-cache will just abort.
		f$info$x509 = e;
		}
	}
