##! Perform full certificate chain validation for SSL certificates.
#
# Also caches all intermediate certificates encountered so far and use them
# for future validations.

@load base/frameworks/cluster
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
		## Result of certificate validation for this connection, given
		## as OpenSSL validation code.
		validation_code: int &optional;
		## Ordered chain of validated certificate, if validation succeeded.
		valid_chain: vector of opaque of x509 &optional;
	};

	## Result values for recently validated chains along with the
	## validation status are kept in this table to avoid constant
	## validation every time the same certificate chain is seen.
	global recently_validated_certs: table[string] of X509::Result = table()
		&read_expire=5mins &redef;

	## Use intermediate CA certificate caching when trying to validate
	## certificates. When this is enabled, Zeek keeps track of all valid
	## intermediate CA certificates that it has seen in the past. When
	## encountering a host certificate that cannot be validated because
	## of missing intermediate CA certificate, the cached list is used
	## to try to validate the cert. This is similar to how Firefox is
	## doing certificate validation.
	##
	## Disabling this will usually greatly increase the number of validation warnings
	## that you encounter. Only disable if you want to find misconfigured servers.
	global ssl_cache_intermediate_ca: bool = T &redef;

	## Store the valid chain in c$ssl$valid_chain if validation succeeds.
	## This has a potentially high memory impact, depending on the local environment
	## and is thus disabled by default.
	global ssl_store_valid_chain: bool = F &redef;

	## Event from a manager to workers when encountering a new, valid
	## intermediate.
	global intermediate_add: event(key: string, value: vector of opaque of x509);

	## Event from workers to the manager when a new intermediate chain
	## is to be added.
	global new_intermediate: event(key: string, value: vector of opaque of x509);
}

global intermediate_cache: table[string] of vector of opaque of x509;

@if ( Cluster::is_enabled() )
event zeek_init()
	{
	Broker::auto_publish(Cluster::worker_topic, SSL::intermediate_add);
	Broker::auto_publish(Cluster::manager_topic, SSL::new_intermediate);
	}
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

function cache_validate(chain: vector of opaque of x509): X509::Result
	{
	local chain_hash: vector of string = vector();

	for ( i in chain )
		chain_hash[i] = sha1_hash(x509_get_certificate_string(chain[i]));

	local chain_id = join_string_vec(chain_hash, ".");

	# If we tried this certificate recently, just return the cached result.
	if ( chain_id in recently_validated_certs )
		return recently_validated_certs[chain_id];

	local result = x509_verify(chain, root_certs);
	if ( ! ssl_store_valid_chain && result?$chain_certs )
		recently_validated_certs[chain_id] = X509::Result($result=result$result, $result_string=result$result_string);
	else
		recently_validated_certs[chain_id] = result;

	# if we have a working chain where we did not store the intermediate certs
	# in our cache yet - do so
	if ( ssl_cache_intermediate_ca &&
	     result$result_string == "ok" &&
		   result?$chain_certs &&
		   |result$chain_certs| > 2 )
		{
		local result_chain = result$chain_certs;
		local isnh = x509_subject_name_hash(result_chain[1], 4); # SHA256
		if ( isnh !in intermediate_cache )
			{
			local cachechain: vector of opaque of x509;
			for ( i in result_chain )
				{
				if ( i >=1 && i<=|result_chain|-2 )
					cachechain[i-1] = result_chain[i];
				}
			add_to_cache(isnh, cachechain);
			}
		}

	return result;
	}

hook ssl_finishing(c: connection) &priority=20
	{
	# If there aren't any certs we can't very well do certificate validation.
	if ( ! c$ssl?$cert_chain || |c$ssl$cert_chain| == 0 ||
	     ! c$ssl$cert_chain[0]?$x509 )
		return;

	local intermediate_chain: vector of opaque of x509 = vector();
	local issuer_name_hash = x509_issuer_name_hash(c$ssl$cert_chain[0]$x509$handle, 4); # SHA256
	local hash = c$ssl$cert_chain[0]$sha1;
	local result: X509::Result;

	# Look if we already have a working chain for the issuer of this cert.
	# If yes, try this chain first instead of using the chain supplied from
	# the server.
	if ( ssl_cache_intermediate_ca && issuer_name_hash in intermediate_cache )
		{
		intermediate_chain[0] = c$ssl$cert_chain[0]$x509$handle;
		for ( i in intermediate_cache[issuer_name_hash] )
			intermediate_chain[i+1] = intermediate_cache[issuer_name_hash][i];

		result = cache_validate(intermediate_chain);
		if ( result$result_string == "ok" )
			{
			c$ssl$validation_status = result$result_string;
			c$ssl$validation_code = result$result;
			if ( result?$chain_certs )
				c$ssl$valid_chain = result$chain_certs;
			return;
			}
		}

	# Validation with known chains failed or there was no fitting intermediate
	# in our store.
	# Fall back to validating the certificate with the server-supplied chain.
	local chain: vector of opaque of x509 = vector();
	for ( i in c$ssl$cert_chain )
		{
		if ( c$ssl$cert_chain[i]?$x509 )
			chain[i] = c$ssl$cert_chain[i]$x509$handle;
		}

	result = cache_validate(chain);
	c$ssl$validation_status = result$result_string;
	c$ssl$validation_code = result$result;
	if ( result?$chain_certs )
		c$ssl$valid_chain = result$chain_certs;

	if ( result$result_string != "ok" )
		{
		local message = fmt("SSL certificate validation failed with (%s)", c$ssl$validation_status);
		NOTICE([$note=Invalid_Server_Cert, $msg=message,
		        $sub=c$ssl$cert_chain[0]$x509$certificate$subject, $conn=c,
		        $fuid=c$ssl$cert_chain[0]$fuid,
		        $identifier=cat(c$id$resp_h,c$id$resp_p,hash,c$ssl$validation_code)]);
		}
	}
