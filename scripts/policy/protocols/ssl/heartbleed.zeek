##! Detect the TLS heartbleed attack. See http://heartbleed.com for more.

@load base/protocols/ssl
@load base/frameworks/notice

module Heartbleed;

export {
	redef enum Notice::Type += {
		## Indicates that a host performed a heartbleed attack or scan.
		SSL_Heartbeat_Attack,
		## Indicates that a host performing a heartbleed attack was probably successful.
		SSL_Heartbeat_Attack_Success,
		## Indicates we saw heartbeat requests with odd length. Probably an attack or scan.
		SSL_Heartbeat_Odd_Length,
		## Indicates we saw many heartbeat requests without a reply. Might be an attack.
		SSL_Heartbeat_Many_Requests
	};
}

# Do not disable analyzers after detection - otherwise we will not notice
# encrypted attacks.
redef SSL::disable_analyzer_after_detection=F;

redef record SSL::Info += {
	last_originator_heartbeat_request_size: count &optional;
	last_responder_heartbeat_request_size: count &optional;

	originator_heartbeats: count &default=0;
	responder_heartbeats: count &default=0;

	# Unencrypted connections - was an exploit attempt detected yet.
	heartbleed_detected: bool &default=F;

	# Count number of appdata packages and bytes exchanged so far.
	enc_appdata_packages: count &default=0;
	enc_appdata_bytes: count &default=0;
};

type min_length: record {
	cipher: pattern;
	min_length: count;
};

global min_lengths: vector of min_length = vector();
global min_lengths_tls11: vector of min_length = vector();

event zeek_init()
	{
	# Minimum length a heartbeat packet must have for different cipher suites.
	# Note - tls 1.1f and 1.0 have different lengths :(
	# This should be all cipher suites usually supported by vulnerable servers.
	min_lengths_tls11 += [$cipher=/_AES_256_GCM_SHA384$/, $min_length=43];
	min_lengths_tls11 += [$cipher=/_AES_128_GCM_SHA256$/, $min_length=43];
	min_lengths_tls11 += [$cipher=/_256_CBC_SHA384$/, $min_length=96];
	min_lengths_tls11 += [$cipher=/_256_CBC_SHA256$/, $min_length=80];
	min_lengths_tls11 += [$cipher=/_256_CBC_SHA$/, $min_length=64];
	min_lengths_tls11 += [$cipher=/_128_CBC_SHA256$/, $min_length=80];
	min_lengths_tls11 += [$cipher=/_128_CBC_SHA$/, $min_length=64];
	min_lengths_tls11 += [$cipher=/_3DES_EDE_CBC_SHA$/, $min_length=48];
	min_lengths_tls11 += [$cipher=/_SEED_CBC_SHA$/, $min_length=64];
	min_lengths_tls11 += [$cipher=/_IDEA_CBC_SHA$/, $min_length=48];
	min_lengths_tls11 += [$cipher=/_DES_CBC_SHA$/, $min_length=48];
	min_lengths_tls11 += [$cipher=/_DES40_CBC_SHA$/, $min_length=48];
	min_lengths_tls11 += [$cipher=/_RC4_128_SHA$/, $min_length=39];
	min_lengths_tls11 += [$cipher=/_RC4_128_MD5$/, $min_length=35];
	min_lengths_tls11 += [$cipher=/_RC4_40_MD5$/, $min_length=35];
	min_lengths_tls11 += [$cipher=/_RC2_CBC_40_MD5$/, $min_length=48];
	min_lengths += [$cipher=/_256_CBC_SHA$/, $min_length=48];
	min_lengths += [$cipher=/_128_CBC_SHA$/, $min_length=48];
	min_lengths += [$cipher=/_3DES_EDE_CBC_SHA$/, $min_length=40];
	min_lengths += [$cipher=/_SEED_CBC_SHA$/, $min_length=48];
	min_lengths += [$cipher=/_IDEA_CBC_SHA$/, $min_length=40];
	min_lengths += [$cipher=/_DES_CBC_SHA$/, $min_length=40];
	min_lengths += [$cipher=/_DES40_CBC_SHA$/, $min_length=40];
	min_lengths += [$cipher=/_RC4_128_SHA$/, $min_length=39];
	min_lengths += [$cipher=/_RC4_128_MD5$/, $min_length=35];
	min_lengths += [$cipher=/_RC4_40_MD5$/, $min_length=35];
	min_lengths += [$cipher=/_RC2_CBC_40_MD5$/, $min_length=40];
	}

event ssl_heartbeat(c: connection, is_client: bool, length: count, heartbeat_type: count, payload_length: count, payload: string)
	{
	if ( ! c?$ssl )
		return;

	if ( heartbeat_type == 1 )
		{
		local checklength: count = (length<(3+16)) ? length : (length - 3 - 16);

		if ( payload_length > checklength )
			{
			c$ssl$heartbleed_detected = T;
			NOTICE([$note=Heartbleed::SSL_Heartbeat_Attack,
				$msg=fmt("An TLS heartbleed attack was detected! Record length %d. Payload length %d", length, payload_length),
				$conn=c,
				$identifier=cat(c$uid, length, payload_length)
				]);
			}
		else if ( is_client )
			{
			NOTICE([$note=Heartbleed::SSL_Heartbeat_Attack,
				$msg=fmt("Heartbeat request before encryption. Probable Scan without exploit attempt. Message length: %d. Payload length: %d", length, payload_length),
				$conn=c,
				$n=length,
				$identifier=cat(c$uid, length)
				]);
			}
		}

	if ( heartbeat_type == 2 && c$ssl$heartbleed_detected )
		{
			NOTICE([$note=Heartbleed::SSL_Heartbeat_Attack_Success,
				$msg=fmt("An TLS heartbleed attack detected before was probably exploited. Message length: %d. Payload length: %d", length, payload_length),
				$conn=c,
				$identifier=c$uid
				]);
		}
	}

event ssl_encrypted_heartbeat(c: connection, is_client: bool, length: count)
	{
	if ( is_client )
		++c$ssl$originator_heartbeats;
	else
		++c$ssl$responder_heartbeats;

	local duration = network_time() - c$start_time;

	if ( c$ssl$enc_appdata_packages == 0 )
			NOTICE([$note=SSL_Heartbeat_Attack,
				$msg=fmt("Heartbeat before ciphertext. Probable attack or scan. Length: %d, is_client: %d", length, is_client),
				$conn=c,
				$n=length,
				$identifier=fmt("%s%s", c$uid, "early")
				]);
	else if ( duration < 1min )
			NOTICE([$note=SSL_Heartbeat_Attack,
				$msg=fmt("Heartbeat within first minute. Possible attack or scan. Length: %d, is_client: %d, time: %s", length, is_client, duration),
				$conn=c,
				$n=length,
				$identifier=fmt("%s%s", c$uid, "early")
				]);

	if ( c$ssl$originator_heartbeats > c$ssl$responder_heartbeats + 3 )
			NOTICE([$note=SSL_Heartbeat_Many_Requests,
				$msg=fmt("More than 3 heartbeat requests without replies from server. Possible attack. Client count: %d, server count: %d", c$ssl$originator_heartbeats, c$ssl$responder_heartbeats),
				$conn=c,
				$n=(c$ssl$originator_heartbeats-c$ssl$responder_heartbeats),
				$identifier=fmt("%s%d", c$uid, c$ssl$responder_heartbeats/1000) # re-throw every 1000 heartbeats
				]);

	if ( c$ssl$responder_heartbeats > c$ssl$originator_heartbeats + 3 )
			NOTICE([$note=SSL_Heartbeat_Many_Requests,
				$msg=fmt("Server sending more heartbeat responses than requests seen. Possible attack. Client count: %d, server count: %d", c$ssl$originator_heartbeats, c$ssl$responder_heartbeats),
				$conn=c,
				$n=(c$ssl$responder_heartbeats-c$ssl$originator_heartbeats),
				$identifier=fmt("%s%d", c$uid, c$ssl$responder_heartbeats/1000) # re-throw every 1000 heartbeats
				]);

	if ( is_client && length < 19 )
			NOTICE([$note=SSL_Heartbeat_Odd_Length,
				$msg=fmt("Heartbeat message smaller than minimum required length. Probable attack or scan. Message length: %d. Cipher: %s. Time: %f", length, c$ssl$cipher, duration),
				$conn=c,
				$n=length,
				$identifier=fmt("%s-weak-%d", c$uid, length)
				]);

	# Examine request lengths based on used cipher...
	local min_length_choice: vector of min_length;
	if ( (c$ssl$version == "TLSv11") || (c$ssl$version == "TLSv12") ) # tls 1.1+ have different lengths for CBC
		min_length_choice = min_lengths_tls11;
	else
		min_length_choice = min_lengths;

	for ( i in min_length_choice )
		{
		if ( min_length_choice[i]$cipher in c$ssl$cipher )
			{
			if ( length < min_length_choice[i]$min_length )
				{
				NOTICE([$note=SSL_Heartbeat_Odd_Length,
					$msg=fmt("Heartbeat message smaller than minimum required length. Probable attack. Message length: %d. Required length: %d. Cipher: %s. Cipher match: %s", length, min_length_choice[i]$min_length, c$ssl$cipher, min_length_choice[i]$cipher),
					$conn=c,
					$n=length,
					$identifier=fmt("%s-weak-%d", c$uid, length)
					]);
				}

			break;
			}

		}

	if ( is_client )
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
				$msg=fmt("An encrypted TLS heartbleed attack was probably detected! First packet client record length %d, first packet server record length %d. Time: %f",
					c$ssl$last_originator_heartbeat_request_size, length, duration),
				$conn=c,
				$identifier=c$uid # only throw once per connection
				]);
			}

		else if ( ! c$ssl?$last_originator_heartbeat_request_size )
			c$ssl$last_responder_heartbeat_request_size = length;

		if ( c$ssl?$last_originator_heartbeat_request_size )
			delete c$ssl$last_originator_heartbeat_request_size;
		}
	}

event ssl_encrypted_data(c: connection, is_client: bool, record_version: count, content_type: count, length: count)
	{
	if ( !c?$ssl )
		return;

	if ( content_type == SSL::HEARTBEAT )
		event ssl_encrypted_heartbeat(c, is_client, length);
	else if ( (content_type == SSL::APPLICATION_DATA) && (length > 0) )
		{
		++c$ssl$enc_appdata_packages;
		c$ssl$enc_appdata_bytes += length;
		}
	}
