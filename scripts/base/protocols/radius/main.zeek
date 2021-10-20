##! Implements base functionality for RADIUS analysis. Generates the radius.log file.

@load ./consts
@load base/utils/addrs
@load base/protocols/conn/removal-hooks

module RADIUS;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	type Info: record {
		## Timestamp for when the event happened.
		ts           : time     &log;
		## Unique ID for the connection.
		uid          : string   &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id           : conn_id  &log;
		## The username, if present.
		username     : string   &log &optional;
		## MAC address, if present.
		mac          : string   &log &optional;
		## The address given to the network access server, if
		## present.  This is only a hint from the RADIUS server
		## and the network access server is not required to honor
		## the address.
		framed_addr  : addr     &log &optional;
		## Address (IPv4, IPv6, or FQDN) of the initiator end of the tunnel,
		## if present.  This is collected from the Tunnel-Client-Endpoint
		## attribute.
		tunnel_client: string   &log &optional;
		## Connect info, if present.
		connect_info : string   &log &optional;
		## Reply message from the server challenge. This is
		## frequently shown to the user authenticating.
		reply_msg    : string   &log &optional;
		## Successful or failed authentication.
		result       : string   &log &optional;
		## The duration between the first request and
		## either the "Access-Accept" message or an error.
		## If the field is empty, it means that either
		## the request or response was not seen.
		ttl          : interval &log &optional;

		## Whether this has already been logged and can be ignored.
		logged       : bool     &default=F;
	};

	## Event that can be handled to access the RADIUS record as it is sent on
	## to the logging framework.
	global log_radius: event(rec: Info);

	## RADIUS finalization hook.  Remaining RADIUS info may get logged when it's called.
	global finalize_radius: Conn::RemovalHook;
}

redef record connection += {
	radius: Info &optional;
};

const ports = { 1812/udp };
redef likely_server_ports += { ports };

event zeek_init() &priority=5
	{
	Log::create_stream(RADIUS::LOG, [$columns=Info, $ev=log_radius, $path="radius", $policy=log_policy]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_RADIUS, ports);
	}

event radius_message(c: connection, result: RADIUS::Message) &priority=5
	{
	if ( ! c?$radius )
		{
		c$radius = Info($ts  = network_time(),
		                $uid = c$uid,
		                $id  = c$id);
		Conn::register_removal_hook(c, finalize_radius);
		}

	switch ( RADIUS::msg_types[result$code] )
		{
		case "Access-Request":
			if ( result?$attributes )
				{
				# User-Name
				if ( ! c$radius?$username && 1 in result$attributes )
					c$radius$username = result$attributes[1][0];

				# Calling-Station-Id (we expect this to be a MAC)
				if ( ! c$radius?$mac && 31 in result$attributes )
					c$radius$mac = normalize_mac(result$attributes[31][0]);

				# Tunnel-Client-EndPoint (useful for VPNs)
				if ( ! c$radius?$tunnel_client && 66 in result$attributes )
					c$radius$tunnel_client = result$attributes[66][0];

				# Connect-Info
				if ( ! c$radius?$connect_info && 77 in result$attributes )
					c$radius$connect_info = result$attributes[77][0];
				}
			break;

		case "Access-Challenge":
			if ( result?$attributes )
				{
				# Framed-IP-Address
				if ( ! c$radius?$framed_addr && 8 in result$attributes )
					c$radius$framed_addr = raw_bytes_to_v4_addr(result$attributes[8][0]);

				if ( ! c$radius?$reply_msg && 18 in result$attributes )
					c$radius$reply_msg = result$attributes[18][0];
				}
			break;

		case "Access-Accept":
			c$radius$result = "success";
			break;

		case "Access-Reject":
			c$radius$result = "failed";
			break;

		# TODO: Support RADIUS accounting. (add port 1813/udp above too)
		#case "Accounting-Request":
		#	break;
		#
		#case "Accounting-Response":
		#	break;
		}
	}

event radius_message(c: connection, result: RADIUS::Message) &priority=-5
	{
	if ( c$radius?$result )
		{
		local ttl = network_time() - c$radius$ts;
		if ( ttl != 0secs )
			c$radius$ttl = ttl;

		Log::write(RADIUS::LOG, c$radius);

		delete c$radius;
		}
	}

hook finalize_radius(c: connection)
	{
	if ( c?$radius && ! c$radius$logged )
		{
		c$radius$result = "unknown";
		Log::write(RADIUS::LOG, c$radius);
		}
	}
