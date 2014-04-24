# Detect the TLS heartbleed attack. See http://heartbleed.com

@load base/protocols/ssl
@load base/frameworks/notice

module Heartbleed;

# Do not disable analyzers after detection - otherwhise we will not notice encrypted attacks
redef SSL::disable_analyzer_after_detection=F;

redef record SSL::Info += {
	last_originator_heartbeat_request_size: count &optional;
	last_responder_heartbeat_request_size: count &optional;
	originator_heartbeats: count &default=0;
	responder_heartbeats: count &default=0;

	heartbleed_detected: bool &default=F;
	};

export {
	redef enum Notice::Type += {
		## Indicates that a host performing a heartbleed attack.
		SSL_Heartbeat_Attack,
		## Indicates that a host performing a heartbleed attack was probably successful.
		SSL_Heartbeat_Attack_Success,
		## Indicates we saw heartbeat requests with odd length. Probably an attack.
		SSL_Heartbeat_Odd_Length,
		## Indicates we saw many heartbeat requests without an reply. Might be an attack.
		SSL_Heartbeat_Many_Requests
	};
}

event ssl_heartbeat(c: connection, is_orig: bool, length: count, heartbeat_type: count, payload_length: count, payload: string)
	{
	if ( heartbeat_type == 1 )
		{
		local checklength: count = (length<(3+16)) ? length : (length - 3 - 16);

		if ( payload_length > checklength )
			{
			c$ssl$heartbleed_detected = T;
			NOTICE([$note=SSL_Heartbeat_Attack,
				$msg=fmt("An TLS heartbleed attack was detected! Record length %d, payload length %d", length, payload_length),
				$conn=c,
				$identifier=cat(c$uid, length, payload_length)
				]);
			}
		}

	if ( heartbeat_type == 2 && c$ssl$heartbleed_detected )
		{
			NOTICE([$note=SSL_Heartbeat_Attack_Success,
				$msg=fmt("An TLS heartbleed attack detected before was probably exploited. Transmitted payload length in first packet: %d", payload_length),
				$conn=c,
				$identifier=c$uid
				]);
		}
	}

event ssl_encrypted_heartbeat(c: connection, is_orig: bool, length: count)
	{
	if ( is_orig )
		++c$ssl$originator_heartbeats;
	else
		++c$ssl$responder_heartbeats;

	if ( c$ssl$originator_heartbeats > c$ssl$responder_heartbeats + 3 )
			NOTICE([$note=SSL_Heartbeat_Many_Requests,
				$msg=fmt("Seeing more than 3 heartbeat requests without replies from server. Possible attack. Client count: %d, server count: %d", c$ssl$originator_heartbeats, c$ssl$responder_heartbeats),
				$conn=c,
				$n=(c$ssl$originator_heartbeats-c$ssl$responder_heartbeats),
				$identifier=fmt("%s%d", c$uid, c$ssl$responder_heartbeats/1000) # re-throw every 1000 heartbeats
				]);

	if ( c$ssl$responder_heartbeats > c$ssl$originator_heartbeats + 3 )
			NOTICE([$note=SSL_Heartbeat_Many_Requests,
				$msg=fmt("Server is sending more heartbleed responsed than requests were seen. Possible attack. Client count: %d, server count: %d", c$ssl$originator_heartbeats, c$ssl$responder_heartbeats),
				$conn=c,
				$n=(c$ssl$originator_heartbeats-c$ssl$responder_heartbeats),
				$identifier=fmt("%s%d", c$uid, c$ssl$responder_heartbeats/1000) # re-throw every 1000 heartbeats
				]);

	if ( is_orig && length < 19 )
			NOTICE([$note=SSL_Heartbeat_Odd_Length,
				$msg=fmt("Heartbeat message smaller than minimum required length. Probable attack. Message length: %d", length),
				$conn=c,
				$n=length,
				$identifier=cat(c$uid, length)
				]);

	if ( is_orig )
		{
		if ( c$ssl?$last_responder_heartbeat_request_size )
			{
			# server originated heartbeat. Ignore & continue
			delete c$ssl$last_responder_heartbeat_request_size;
			}
		else
			c$ssl$last_originator_heartbeat_request_size = length;
		}
	else
		{
		if ( c$ssl?$last_originator_heartbeat_request_size && c$ssl$last_originator_heartbeat_request_size < length )
			{
			NOTICE([$note=SSL_Heartbeat_Attack_Success,
				$msg=fmt("An Encrypted TLS heartbleed attack was probably detected! First packet client record length %d, first packet server record length %d",
					c$ssl?$last_originator_heartbeat_request_size, c$ssl$last_originator_heartbeat_request_size),
				$conn=c,
				$identifier=c$uid # only throw once per connection
				]);
			}
		else if ( ! c$ssl?$last_originator_heartbeat_request_size )
			{
			c$ssl$last_responder_heartbeat_request_size = length;
			}

		if ( c$ssl?$last_originator_heartbeat_request_size )
			delete c$ssl$last_originator_heartbeat_request_size;
		}
	}
