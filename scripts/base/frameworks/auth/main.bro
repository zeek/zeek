##! Authentication framework for tracking authentication activity
##! in realtime alongside network traffic.

module Auth;

export {
	## Create the log stream.
	redef enum Log::ID += { LOG };

	## The authentication endpoint is representative of the host where the 
	## login attempted originated from. 
	type Endpoint: record {
		## The host that the login originated from.
		host:  addr    &log &optional;
		## If the login was over 802.1x then the authentication endpoint is a
		## mac address. 
		mac:   string  &log &optional;
	};

	type Action: enum {
		Login,
		Modify,
		Logout
	};

	type Info: record {
		## Timestamp for the login.
		ts:             time         &log;
		## Describes the action taking place.
		action:         Auth::Action &log &default=Login;
		## The username seen during the login.
		username:       string       &log;
		## Abstracted endpoint for the authentication originator.
		endpoint:       Endpoint     &log;
		## An arbitrary string for the local name given to a particular
		## service that a user logged into. 
		## (e.g. "Corporate VPN" or "Kerberos")
		service:        string       &log;
		## Indicates whether or not the hardware underneath has been 
		## changed. This mostly applies to 802.1x authentication.
		hardware_auth:  bool         &log &default=F;
		## Authentication method; password, key, etc.
		method:         string       &log &optional;
		## Status of the login attempt.
		success:        bool         &log &default=T;
		## The tetual reason for the login failure if the login attempt failed
		## and a reason for the failure is available.
		failure_reason: string       &log &optional;
		## If the service logged into was something like a VPN that will 
		## give the user another IP address, that new IP address will 
		## be stored here.
		acquired_host:  addr         &log &optional;
	};

	## Used to get auth records associated with an endpoint.
	global get_auths: function(e: Endpoint): set[Info];

	## Used to get auth records associated with a user.
	global get_systems: function(user: string): set[Info];
	
	## Used to process a login and store an auth record.
	global do_login: function(rec: Info);
	
	## Used to update an auth record after it has been stored.
	global modify_login: function(old: Info, new: Info);
	
	## Used to update the auth record store and remove entries.
	global do_logout: function(rec: Info);

	## Event fired when a login is seen and first recorded.
	global login: event(rec: Info);
	
	## Event fired when login record attributes are changed.
	global login_modified: event(old: Info, new: Info);
	
	## Event fired when logout is seen and records are removed.
	global logout: event(rec: Info);
}

# Index of user auth records by IP address.
global auth_index_ip: table[addr] of set[Info];
# Index of user auth records by MAC address.
global auth_index_mac: table[string] of set[Info];
# Index of user auth records by IP address. 
global auth_index_username: table[string] of set[Info];

event bro_init() &priority=5
	{
	Log::create_stream(Auth::LOG, [$columns=Info]);
	}

function get_users(ep: Endpoint): set[Info]
	{
	local results:  set[Info] = set();
	if ( ep?$host && ep$host in auth_index_ip )
		for ( rec in auth_index_ip[ep$host] )
			add results[rec];
	if ( ep?$mac && ep$mac in auth_index_mac )
		for ( rec in auth_index_mac[ep$mac] )
			add results[rec];
	return results;
	}

function get_systems(user: string): set[Info]
	{
	if ( user in auth_index_username )
		return auth_index_username[user];
	else
		return set();
	}

function cleanup_entry(rec: Info)
	{
	rec$ts=network_time();
	if ( rec$endpoint?$host && rec$endpoint$host in auth_index_ip && rec in auth_index_ip[rec$endpoint$host] )
		delete auth_index_ip[rec$endpoint$host][rec];
	if ( rec$endpoint?$mac && rec$endpoint$mac in auth_index_mac && rec in auth_index_mac[rec$endpoint$mac] )
		delete auth_index_mac[rec$endpoint$mac][rec];
	if ( rec in auth_index_username[rec$username] )
		delete auth_index_username[rec$username][rec];
	}

function add_entry(rec: Info)
	{
	rec$ts=network_time();
	if ( rec$endpoint?$host )
		{
		if ( rec$endpoint$host in auth_index_ip )
			add auth_index_ip[rec$endpoint$host][rec];
		else
			auth_index_ip[rec$endpoint$host] = set(rec);
		}
	if ( rec$endpoint?$mac )
		{
		if ( rec$endpoint$mac in auth_index_mac )
			{
			add auth_index_mac[rec$endpoint$mac][rec];
			}
		else
			auth_index_mac[rec$endpoint$mac] = set(rec);
		}
	if ( rec$username in auth_index_username )
		{
		add auth_index_username[rec$username][rec];
		}
	else
		{
		auth_index_username[rec$username] = set(rec);
		}
	}

function same_endpoints(old: Endpoint, new: Endpoint): bool
	{
	# Doing record value comparison by creatively "using"
	# the serializer.  If the values in the records are the
	# same they will serialize to the same value and the length
	# of the set will be 1.
	if ( |set(old, new)| == 1 )
		return T;
	else
		return F;
	}

function modify_login(old: Info, new: Info)
	{
	if ( ! same_endpoints(old$endpoint, new$endpoint) )
		{
		new$action = Auth::Modify;
		cleanup_entry(old);
		add_entry(new);
		event Auth::login_modified(old, new);
		}
	}

function do_login(rec: Info)
	{
	# TODO: Check for true value in hardware_auth and clear previous entries
	if ( rec$hardware_auth )
		{
		for ( authrecord in get_users(rec$endpoint) )
			{
			do_logout(authrecord);
			}
		}
	if ( rec$success )
		{
		add_entry(rec);
		}
	rec$action = Login;
	
	event Auth::login(rec);
	}

function do_logout(rec: Info)
	{
	cleanup_entry(rec);
	rec$action = Logout;

	event Auth::logout(rec);
	}

event Auth::login(rec: Info) &priority=-5
	{
	Log::write(LOG, rec);
	}

event Auth::login_modified(old: Info, new: Info) &priority=-5
	{
	Log::write(LOG, new);
	}

event Auth::logout(rec: Info) &priority=-5
	{
	Log::write(LOG, rec);
	}
