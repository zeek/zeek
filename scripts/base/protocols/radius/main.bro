##! Implements base functionality for RADIUS analysis. Generates the radius.log file.

module RADIUS;

@load ./consts.bro
@load base/utils/addrs

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp for when the event happened.
		ts		: time    &log;
		## Unique ID for the connection.
		uid		: string  &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id		: conn_id &log;
		## The username, if present.
		username	: string &log &optional;
		## MAC address, if present.
		mac		: string &log &optional;
		## Remote IP address, if present.
		remote_ip       : addr &log &optional;
		## Connect info, if present.
		connect_info	: string &log &optional;
		## Successful or failed authentication.
		result		: string &log &optional;
		## Whether this has already been logged and can be ignored.
		logged		: bool &optional;

	};

	## The amount of time we wait for an authentication response before
	## expiring it.
	const expiration_interval = 10secs &redef;

	## Logs an authentication attempt if we didn't see a response in time.
	##
	## t: A table of Info records.
	##
	## idx: The index of the connection$radius table corresponding to the
	##      radius authentication about to expire.
	##
	## Returns: 0secs, which when this function is used as an
	##          :bro:attr:`&expire_func`, indicates to remove the element at
	##          *idx* immediately.
	global expire: function(t: table[count] of Info, idx: count): interval;

	## Event that can be handled to access the RADIUS record as it is sent on
	## to the loggin framework.
	global log_radius: event(rec: Info);
}

redef record connection += {
	radius: table[count] of Info &optional &write_expire=expiration_interval &expire_func=expire;
};

const ports = { 1812/udp };

event bro_init() &priority=5
	{
	Log::create_stream(RADIUS::LOG, [$columns=Info, $ev=log_radius, $path="radius"]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_RADIUS, ports);
	}

event radius_message(c: connection, result: RADIUS::Message)
	{
	local info: Info;

	if ( c?$radius && result$trans_id in c$radius )
		info = c$radius[result$trans_id];
	else
		{
		c$radius = table();
		info$ts  = network_time();
		info$uid = c$uid;
		info$id  = c$id;
		}

	switch ( RADIUS::msg_types[result$code] ) {
		case "Access-Request":
			if ( result?$attributes ) {
				# User-Name
				if ( ! info?$username && 1 in result$attributes )
					info$username = result$attributes[1][0];

				# Calling-Station-Id (we expect this to be a MAC)
				if ( ! info?$mac && 31 in result$attributes )
					info$mac = normalize_mac(result$attributes[31][0]);

				# Tunnel-Client-EndPoint (useful for VPNs)
				if ( ! info?$remote_ip && 66 in result$attributes )
					info$remote_ip = to_addr(result$attributes[66][0]);

				# Connect-Info
				if ( ! info?$connect_info && 77 in result$attributes )
					info$connect_info = result$attributes[77][0];
			}

			break;

		case "Access-Accept":
			info$result = "success";
			break;

		case "Access-Reject":
			info$result = "failed";
			break;
	}

	if ( info?$result && ! info?$logged )
		{
		info$logged = T;
		Log::write(RADIUS::LOG, info);
		}

	c$radius[result$trans_id] = info;
	}


function expire(t: table[count] of Info, idx: count): interval
	 {
	 t[idx]$result = "unknown";
	 Log::write(RADIUS::LOG, t[idx]);
	 return 0secs;
	 }
