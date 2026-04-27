##! Log information about certificates while attempting to avoid duplicate
##! logging.

@load base/utils/directions-and-hosts
@load base/protocols/ssl
@load base/files/x509
@load base/frameworks/cluster

@load base/frameworks/storage/async
@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/sqlite

module Known;

export {
	redef enum Log::ID += { CERTS_LOG };

	global log_policy_certs: Log::PolicyHook;

	type CertsInfo: record {
		## The timestamp when the certificate was detected.
		ts:             time   &log;
		## The address that offered the certificate.
		host:           addr   &log;
		## If the certificate was handed out by a server, this is the
		## port that the server was listening on.
		port_num:       port   &log &optional;
		## Certificate subject.
		subject:        string &log &optional;
		## Certificate issuer subject.
		issuer_subject: string &log &optional;
		## Serial number for the certificate.
		serial:         string &log &optional;
	};

	## The certificates whose existence should be logged and tracked.
	## Choices are: LOCAL_HOSTS, REMOTE_HOSTS, ALL_HOSTS, NO_HOSTS.
	option cert_tracking = LOCAL_HOSTS;

	## Use the storage framework to enable persistence of the stored
	## certs between runs.
	const enable_certs_persistence = F &redef;

	## Toggles between different implementations of this script.
	## When true, use a Broker data store, else use a regular Zeek set
	## with keys uniformly distributed over proxy nodes in cluster
	## operation.
	const use_cert_store = F &redef &deprecated="Remove in v9.1. Store support has been disabled by default since Zeek 6.0 due to performance issues and will be removed.";

	type AddrCertHashPair: record {
		host: addr;
		hash: string;
	};

	## Storage configuration for Broker stores

	## Holds the set of all known certs.  Keys in the store are
	## :zeek:type:`Known::AddrPortServTriplet` and their associated value is
	## always the boolean value of "true".
	global cert_broker_store: Cluster::StoreInfo;

	## The Broker topic name to use for :zeek:see:`Known::cert_broker_store`.
	const cert_store_name = "zeek/known/certs" &redef;

	## Storage configuration for storage framework stores

	## This requires setting a configuration in local.zeek that sets the
	## Known::enable_certs_persistence boolean to T, and optionally setting different
	## values in the Known::cert_store_backend_options record.

	## Backend to use for storing known certs data using the storage framework.
	global cert_store_backend: opaque of Storage::BackendHandle;

	## The name to use for :zeek:see:`Known::cert_store_backend`. This will be used
	## by the backends to differentiate tables/keys. This should be alphanumeric so
	## that it can be used as the table name for the storage framework.
	const cert_store_prefix = "zeekknowncerts" &redef;

	## The type of storage backend to open.
	const cert_store_backend_type : Storage::Backend = Storage::STORAGE_BACKEND_SQLITE &redef;

	## The options for the cert store. This should be redef'd in local.zeek to set
	## connection information for the backend. The options default to a memory store.
	const cert_store_backend_options : Storage::BackendOptions = [ $sqlite = [
		$database_path=fmt("%s/known/certs.sqlite", Cluster::default_store_dir),
		$table_name=Known::cert_store_name ]] &redef;

	## The expiry interval of new entries in :zeek:see:`Known::cert_broker_store` and
	## :zeek:see:`Known::cert_store_backend`. This also changes the interval at which
	## certs get logged.
	option cert_store_expiry = 1day;

	## The timeout interval to use for operations against
	## :zeek:see:`Known::cert_broker_store` and
	## :zeek:see:`Known::cert_store_backend`. .
	option cert_store_timeout = 15sec;

	## The set of all known certificates to store for preventing duplicate
	## logging. It can also be used from other scripts to
	## inspect if a certificate has been seen in use. The string value
	## in the set is for storing the DER formatted certificate' SHA1 hash.
	##
	## In cluster operation, this set is uniformly distributed across
	## proxy nodes.
	global certs: set[addr, string] &create_expire=1day &redef;

	## Event that can be handled to access the loggable record as it is sent
	## on to the logging framework.
	global log_known_certs: event(rec: CertsInfo);
}

event zeek_init()
	{
@pragma push ignore-deprecations
	if ( ! Known::use_cert_store && ! Known::enable_certs_persistence )
		return;
@pragma pop ignore-deprecations

@pragma push ignore-deprecations
	if ( Known::use_cert_store )
		{
		Known::cert_broker_store = Cluster::create_store(Known::cert_store_name);
@pragma pop ignore-deprecations
		}
	else
		{
		local res = Storage::Sync::open_backend(Known::cert_store_backend_type, Known::cert_store_backend_options, Known::AddrCertHashPair, bool);
		if ( res$code == Storage::SUCCESS )
			Known::cert_store_backend = res$value;
		else
			Reporter::error(fmt("%s: Failed to open backend connection: %s", Known::cert_store_prefix, res$error_str));
		}
	}

event Known::cert_found(info: CertsInfo, hash: string)
	{
@pragma push ignore-deprecations
	if ( ! Known::use_cert_store && ! Known::enable_certs_persistence )
		return;
@pragma pop ignore-deprecations

	local key = AddrCertHashPair($host = info$host, $hash = hash);

@pragma push ignore-deprecations
	if ( Known::use_cert_store )
		{
@pragma pop ignore-deprecations
		when [info, key] ( local r = Broker::put_unique(Known::cert_broker_store$store, key,
		                                    T, Known::cert_store_expiry) )
			{
			if ( r$status == Broker::SUCCESS )
				{
				if ( r$result as bool )
					Log::write(Known::CERTS_LOG, info);
				}
			else
				Reporter::error(fmt("%s: data store put_unique failure",
				                    Known::cert_store_name));
			}
		timeout Known::cert_store_timeout
			{
			# Can't really tell if master store ended up inserting a key.
			Log::write(Known::CERTS_LOG, info);
			}
		}
	else
		{
		when [info, key] ( local put_res = Storage::Async::put(Known::cert_store_backend, [$key=key, $value=T, $overwrite=F,
		                                                    $expire_time=Known::cert_store_expiry]) )
			{
			print(put_res$code);
			if ( put_res$code == Storage::SUCCESS )
				Log::write(Known::CERTS_LOG, info);
			else if ( put_res$code != Storage::KEY_EXISTS )
				Reporter::error(fmt("%s: data store put_unique failure: %s",
				                    Known::cert_store_name, put_res$error_str));
			}
		timeout Known::cert_store_timeout
			{
			Log::write(Known::CERTS_LOG, info);
			}
		}
	}

event known_cert_add(info: CertsInfo, hash: string)
	{
@pragma push ignore-deprecations
	if ( Known::use_cert_store || Known::enable_certs_persistence )
		return;
@pragma pop ignore-deprecations

	if ( [info$host, hash] in Known::certs )
		return;

	add Known::certs[info$host, hash];

	@if ( ! Cluster::is_enabled() ||
	      Cluster::local_node_type() == Cluster::PROXY )
		Log::write(Known::CERTS_LOG, info);
	@endif
	}

event Known::cert_found(info: CertsInfo, hash: string)
	{
@pragma push ignore-deprecations
	if ( Known::use_cert_store || Known::enable_certs_persistence )
		return;
@pragma pop ignore-deprecations

	if ( [info$host, hash] in Known::certs )
		return;

	local key = cat(info$host, hash);
	Cluster::publish_hrw(Cluster::proxy_pool, key, known_cert_add, info, hash);
	event known_cert_add(info, hash);
	}

event Cluster::node_up(name: string, id: string)
	{
@pragma push ignore-deprecations
	if ( Known::use_cert_store || Known::enable_certs_persistence )
		return;
@pragma pop ignore-deprecations

	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;

	# Drop local suppression cache on workers to force HRW key repartitioning.
	clear_table(Known::certs);
	}

event Cluster::node_down(name: string, id: string)
	{
@pragma push ignore-deprecations
	if ( Known::use_cert_store || Known::enable_certs_persistence )
		return;
@pragma pop ignore-deprecations

	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;

	# Drop local suppression cache on workers to force HRW key repartitioning.
	clear_table(Known::certs);
	}

event ssl_established(c: connection) &priority=3
	{
	if ( ! c$ssl?$cert_chain )
		return;

	if ( |c$ssl$cert_chain| < 1 )
		return;

	if ( ! c$ssl$cert_chain[0]?$x509 )
		return;

	local fuid = c$ssl$cert_chain[0]$fuid;

	if ( ! c$ssl$cert_chain[0]?$sha1 )
		{
		Reporter::error(fmt("Certificate with fuid %s did not contain sha1 hash when checking for known certs. Aborting",
			fuid));
		return;
		}

	local host = c$id$resp_h;

	if ( ! addr_matches_host(host, cert_tracking) )
		return;

	local hash = c$ssl$cert_chain[0]$sha1;
	local cert = c$ssl$cert_chain[0]$x509$certificate;
	local info = CertsInfo($ts = network_time(), $host = host,
	                       $port_num = c$id$resp_p, $subject = cert$subject,
	                       $issuer_subject = cert$issuer,
	                       $serial = cert$serial);
	event Known::cert_found(info, hash);
	}

event zeek_init() &priority=5
	{
	Log::create_stream(Known::CERTS_LOG, Log::Stream($columns=CertsInfo, $ev=log_known_certs, $path="known_certs", $policy=log_policy_certs));
	}
