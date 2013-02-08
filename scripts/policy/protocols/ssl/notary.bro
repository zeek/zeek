@load base/protocols/ssl

module CertNotary;

export {
	## A response from the ICSI certificate notary.
	type Response: record {
		first_seen: count &log &optional;
		last_seen:  count &log &optional;
		times_seen: count &log &optional;
		valid:      bool  &log &optional;
	};

	## The notary domain to query.
	const domain = "notary.icsi.berkeley.edu" &redef;
}

redef record SSL::Info += {
	sha1:   string &log &optional;
	notary: Response &log &optional;
	};

# The DNS cache of notary responses.
global notary_cache: table[string] of Response &create_expire = 1 hr;

# The records that wait for a notary response identified by the cert digest.
# Each digest refers to a list of connection UIDs which are updated when a DNS
# reply arrives asynchronously.
global waitlist: table[string] of vector of SSL::Info;

function clear_waitlist(digest: string)
	{
	if ( digest in waitlist )
		{
		for ( i in waitlist[digest] )
			SSL::undelay_log(waitlist[digest][i], "notary");
		delete waitlist[digest];
		}
	}

event x509_certificate(c: connection, is_orig: bool, cert: X509,
                       chain_idx: count, chain_len: count, der_cert: string)
	{
	if ( is_orig || chain_idx != 0 || ! c?$ssl )
		return;

	local digest = sha1_hash(der_cert);
	c$ssl$sha1 = digest;

	if ( digest in notary_cache )
		{
		c$ssl$notary = notary_cache[digest];
		return;
		}

	SSL::delay_log(c$ssl, "notary");

	local waits_already = digest in waitlist;
	if ( ! waits_already )
		waitlist[digest] = vector();
	waitlist[digest][|waitlist[digest]|] = c$ssl;
	if ( waits_already )
		return;

	when ( local str = lookup_hostname_txt(fmt("%s.%s", digest, domain)) )
		{
		notary_cache[digest] = [];

		# Parse notary answer.
		if ( str == "<???>" ) # NXDOMAIN
			{
			clear_waitlist(digest);
			return;
			}
		local fields = split(str, / /);
		if ( |fields| != 5 ) # version 1 has 5 fields.
			{
			clear_waitlist(digest);
			return;
			}
		local version = split(fields[1], /=/)[2];
		if ( version != "1" )
			{
			clear_waitlist(digest);
			return;
			}
		local r = notary_cache[digest];
		r$first_seen = to_count(split(fields[2], /=/)[2]);
		r$last_seen = to_count(split(fields[3], /=/)[2]);
		r$times_seen = to_count(split(fields[4], /=/)[2]);
		r$valid = split(fields[5], /=/)[2] == "1";

		# Assign notary answer to all records waiting for this digest.
		if ( digest in waitlist )
			{
			for ( i in waitlist[digest] )
				{
				local info = waitlist[digest][i];
				SSL::undelay_log(info, "notary");
				info$notary = r;
				}
			delete waitlist[digest];
			}
		}
	}
