##! Perform full certificate chain validation for SSL certificates.
# Also caches all intermediate certificates encountered so far and use them
# for future validations.

@load base/frameworks/notice
@load base/protocols/ssl

module SSL;

export {
	redef enum Notice::Type += {
		## This notice indicates that the result of validating the
		## certificate along with its full certificate chain was
		## invalid.
		Invalid_Server_Cert
	};

	redef record Info += {
		## Result of certificate validation for this connection.
		validation_status: string &log &optional;
	};

	## MD5 hash values for recently validated chains along with the
	## validation status are kept in this table to avoid constant
	## validation every time the same certificate chain is seen.
	global recently_validated_certs: table[string] of string = table()
		&read_expire=5mins &redef;

	## Event from a worker to the manager that it has encountered a new
	## valid intermediate
	global intermediate_add: event(key: string, value: vector of opaque of x509);

	## Event from the manager to the workers that a new intermediate chain
	## is to be added
	global new_intermediate: event(key: string, value: vector of opaque of x509);
}

global intermediate_cache: table[string] of vector of opaque of x509;

@if ( Cluster::is_enabled() )
@load base/frameworks/cluster
redef Cluster::manager2worker_events += /SSL::intermediate_add/;
redef Cluster::worker2manager_events += /SSL::new_intermediate/;
@endif


function add_to_cache(key: string, value: vector of opaque of x509)
	{
	intermediate_cache[key] = value;
@if ( Cluster::is_enabled() )
	event SSL::new_intermediate(key, value);
@endif
	}

@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
event SSL::intermediate_add(key: string, value: vector of opaque of x509)
	{
	intermediate_cache[key] = value;
	}
@endif

@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
event SSL::new_intermediate(key: string, value: vector of opaque of x509)
	{
	if ( key in intermediate_cache )
		return;

	intermediate_cache[key] = value;
	event SSL::intermediate_add(key, value);
	}
@endif

function cache_validate(chain: vector of opaque of x509): string
	{
	local chain_hash: vector of string = vector();

	for ( i in chain )
		chain_hash[i] = sha1_hash(x509_get_certificate_string(chain[i]));

	local chain_id = join_string_vec(chain_hash, ".");

	# If we tried this certificate recently, just return the cached result.
	if ( chain_id in recently_validated_certs )
		return recently_validated_certs[chain_id];

	local result = x509_verify(chain, root_certs);
	recently_validated_certs[chain_id] = result$result_string;

	# if we have a working chain where we did not store the intermediate certs
	# in our cache yet - do so
	if ( result$result_string == "ok" && result?$chain_certs && |result$chain_certs| > 2 )
		{
		local result_chain = result$chain_certs;
		local icert = x509_parse(result_chain[1]);
		if ( icert$subject !in intermediate_cache )
			{
			local cachechain: vector of opaque of x509;
			for ( i in result_chain )
				{
				if ( i >=1 && i<=|result_chain|-2 )
					cachechain[i-1] = result_chain[i];
				}
			add_to_cache(icert$subject, cachechain);
			}
		}

	return result$result_string;
	}

event ssl_established(c: connection) &priority=3
	{
	# If there aren't any certs we can't very well do certificate validation.
	if ( ! c$ssl?$cert_chain || |c$ssl$cert_chain| == 0 ||
	     ! c$ssl$cert_chain[0]?$x509 )
		return;

	local intermediate_chain: vector of opaque of x509 = vector();
	local issuer = c$ssl$cert_chain[0]$x509$certificate$issuer;
	local result: string;

	# look if we already have a working chain for the issuer of this cert.
	# If yes, try this chain first instead of using the chain supplied from
	# the server.
	if ( issuer in intermediate_cache )
		{
		intermediate_chain[0] = c$ssl$cert_chain[0]$x509$handle;
		for ( i in intermediate_cache[issuer] )
			intermediate_chain[i+1] = intermediate_cache[issuer][i];

		result = cache_validate(intermediate_chain);
		if ( result == "ok" )
			{
			c$ssl$validation_status = result;
			return;
			}
		}

	# validation with known chains failed or there was no fitting intermediate
	# in our store.
	# Fall back to validating the certificate with the server-supplied chain
	local chain: vector of opaque of x509 = vector();
	for ( i in c$ssl$cert_chain )
		{
		if ( c$ssl$cert_chain[i]?$x509 )
			chain[i] = c$ssl$cert_chain[i]$x509$handle;
		}

	result = cache_validate(chain);
	c$ssl$validation_status = result;

	if ( result != "ok" )
		{
		local message = fmt("SSL certificate validation failed with (%s)", c$ssl$validation_status);
		NOTICE([$note=Invalid_Server_Cert, $msg=message,
		        $sub=c$ssl$subject, $conn=c,
		        $identifier=cat(c$id$resp_h,c$id$resp_p,c$ssl$validation_status)]);
		}
	}
