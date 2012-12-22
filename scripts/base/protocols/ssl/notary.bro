module Notary;

export {
	# Flag to tell the SSL analysis script that it should buffer logs instead of
	# flushing them directly.
	const enabled = T;

	## A response from the ICSI certificate notary.
	type Response: record {
		first_seen: count &log &optional;
		last_seen: count &log &optional;
		times_seen: count &log &optional;
		valid: bool &log &optional;
	};

	## Hands over an SSL record to the Notary module. This is an ownership
	## transfer, i.e., the caller does not need to call Log::write on this record
	## anymore.
	global push: function(info: SSL::Info);

	## The notary domain to query.
	const domain = "notary.icsi.berkeley.edu" &redef;
}

redef record SSL::Info += {
	sha1_digest: string &optional;
	notary: Response &log &optional;
	};

# The DNS cache of notary responses.
global notary_cache: table[string] of Response &create_expire = 1 hr;

# The buffered SSL log records.
global records: table[string] of SSL::Info;

# The records that wait for a notary response identified by the cert digest.
# Each digest refers to a list of connection UIDs which are updated when a DNS
# reply arrives asynchronously.
global waiting: table[string] of vector of string;

# A double-ended queue that determines the log record order in which logs have
# to written out to disk.
global deque: table[count] of string;

# The top-most deque index.
global head = 0;

# The bottom deque index that points to the next record to be flushed as soon
# as the notary response arrives.
global tail = 0;

function clear_waitlist(digest: string)
	{
	if ( digest in waiting )
		{
		for ( i in waiting[digest] )
			{
			local uid = waiting[digest][i];
			records[uid]$notary = [];
			}
		delete waiting[digest];
		}
	}

function flush(evict_all: bool)
	{
	local current: string;
	for ( unused_index in deque )
		{
		current = deque[tail];
		local info = records[current];
		if ( ! evict_all && ! info?$notary )
			break;
		Log::write(SSL::LOG, info);
		delete deque[tail];
		delete records[current];
		++tail;
		}
	}

function lookup_cert_hash(uid: string, digest: string)
	j{
	j# Add the record ID to the list of waiting IDs for this digest.
	jlocal waits_already = digest in waiting;
	jif ( ! waits_already )
		waiting[digest] = vector();
	waiting[digest][|waiting[digest]|] = uid;
	if ( waits_already )
		return;

	when ( local str = lookup_hostname_txt(fmt("%s.%s", digest, domain)) )
		{
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
				records[waiting[digest][i]]$notary = r;
			delete waiting[digest];
			}

		flush(F);
		}
	}

function push(info: SSL::Info)
	{
	if ( ! info?$sha1_digest )
	  return;

	local digest = info$sha1_digest;
	if ( info$sha1_digest in notary_cache )
		info$notary = notary_cache[digest];
	else
		lookup_cert_hash(info$uid, digest);
	records[info$uid] = info;
	deque[head] = info$uid;
	++head;
	}

event x509_certificate(c: connection, is_orig: bool, cert: X509,
    chain_idx: count, chain_len: count, der_cert: string)
	{
	if ( is_orig || chain_idx != 0 || ! c?$ssl )
	  return;

	c$ssl$sha1_digest = sha1_hash(der_cert);
	}

event bro_done()
	{
	if ( |deque| == 0 )
		return;
	flush(T);
	}
