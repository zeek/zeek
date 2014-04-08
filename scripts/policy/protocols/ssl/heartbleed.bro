module Heartbleed;

redef record SSL::Info += {
#	last_originator_heartbeat_request_size: count &optional;
#	originator_heartbeats: count &default=0;
#	responder_heartbeats: count &default=0;
  heartbleed_detected: bool &default=F;
	};

export {
	redef enum Notice::Type += {
		## Indicates that a host performing a heartbleed attack.
		SSL_Heartbeat_Attack,
    ## Indicates that a host performing a heartbleed attack was probably successful.
    SSL_Heartbeat_Attack_Success,
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
