module Notary;

export {
	## A response from the ICSI certificate notary.
	type Response: record {
		first_seen: count &log &optional;
		last_seen: count &log &optional;
		times_seen: count &log &optional;
		valid: bool &log &optional;
	};

	## The notary domain to query.
	const domain = "notary.icsi.berkeley.edu" &redef;
}

redef record SSL::Info += {
	sha1: string &log &optional;
	notary: Response &log &optional;
	};

# The DNS cache of notary responses.
global notary_cache: table[string] of Response &create_expire = 1 hr;

# The records that wait for a notary response identified by the cert digest.
# Each digest refers to a list of connection UIDs which are updated when a DNS
# reply arrives asynchronously.
global waiting: table[string] of vector of string;

function clear_waitlist(digest: string)
	{
	print "----- clearing waitlist -----";
	if ( digest in waiting )
		{
		for ( i in waiting[digest] )
			{
      print fmt("----- retrieving %s -----", waiting[digest][i]);
			local info = SSL::clear_delayed_record(waiting[digest][i], "notary");
			info$notary = [];
			}
		delete waiting[digest];
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

  print fmt("----- adding %s -----", c$ssl$uid);
  SSL::add_delayed_record(c$ssl, "notary");

	local waits_already = digest in waiting;
	if ( ! waits_already )
		waiting[digest] = vector();
	waiting[digest][|waiting[digest]|] = c$uid;
	if ( waits_already )
		return;

	when ( local str = lookup_hostname_txt(fmt("%s.%s", digest, domain)) )
		{
    print fmt("----- when for %s: %s -----", digest, str);
		# Cache every response for a digest.
		notary_cache[digest] = [];

		# Parse notary answer.
		if ( str == "<???>" )
			{
			# TODO: Should we handle NXDOMAIN separately?
			clear_waitlist(digest);
			return;
			}
		local fields = split(str, / /);
		if ( |fields| != 5 )	# version 1 has 5 fields.
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

		# Assign notary answer to all waiting records.
		if ( digest in waiting )
			{
			for ( i in waiting[digest] )
			{
			  local info = SSL::clear_delayed_record(waiting[digest][i], "notary");
				info$notary = r;
      }
			delete waiting[digest];
			}
		}
	}
