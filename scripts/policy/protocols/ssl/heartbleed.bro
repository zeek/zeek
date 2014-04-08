module Heartbleed;

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
		## Indicates that a host performing a heartbleed attack was successful.
		SSL_Heartbeat_Attack_Success,
		## Indivcates that a host performing a heartbleed attack after encryption was started was probably successful
		SSL_Heartbeat_Encrypted_Attack_Success,
		## Indicates we saw heartbeet requests with odd length. Probably an attack.
		SSL_Heartbeat_Odd_Length,
		## Indicates we saw many heartbeat requests without an reply. Might be an attack.
		SSL_Heartbeat_Many_Requests
	};
}

event ssl_heartbeat(c: connection, is_orig: bool, length: count, heartbeat_type: count, payload_length: count)
	{
	if ( heartbeat_type == 1 )
		{
		local checklength: count = (length<(3+16)) ? length : (length - 3 - 16);


		if ( payload_length > checklength )
			{
			c$ssl$heartbleed_detected = T;
			NOTICE([$note=SSL_Heartbeat_Attack,
				$msg="An TLS heartbleed attack was detected!",
				$conn=c
				]);
			}
		}

	if ( heartbeat_type == 2 && c$ssl$heartbleed_detected )
		{
			NOTICE([$note=SSL_Heartbeat_Attack_Success,
				$msg="An TLS heartbleed attack was detected and probably exploited",
				$conn=c
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
				$msg="Seeing more than 3 heartbeat requests without replies from server. Possible attack?",
				$conn=c
				]);

	if ( is_orig && length < 19 )
			NOTICE([$note=SSL_Heartbeat_Odd_Length,
				$msg="Heartbeat message smaller than minimum length. Probable attack.",
				$conn=c
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
		if ( c$ssl?$last_originator_heartbeat_request_size && c$ssl$last_originator_heartbeat_request_size > length )
			{
			NOTICE([$note=SSL_Heartbeat_Encrypted_Attack_Success,
				$msg="An Encrypted TLS heartbleed attack was probably detected!",
				$conn=c
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
