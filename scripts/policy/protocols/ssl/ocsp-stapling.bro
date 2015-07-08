#! Log ocsp stapling information

module OCSP_STAPLING;

export {
	redef enum Log::ID += { LOG };
	type Info: record {
		## timestamp
		ts:                 time    &log;

		## status type
		status_type:        count   &log;

		## connection id
		cid:                conn_id &log;

		## connection uid
		cuid:               string  &log;

		## size of this response
		size:               count   &log;
		
		## responseStatus
		responseStatus:     string  &log;

		## responseType
		responseType:       string  &log;

		## version
		version:            count   &log;

		## responderID
		responderID:        string  &log;

		## producedAt
		producedAt:         string  &log;
		
                ## NOTE: the following are specific to one cert id
		##       the above are for one message which may contain
		##       several responses

		## index
		idx:                count   &log  &optional;
		
		## cert id
		cert_id:            OCSP::CertId  &log &optional;

		## certStatus (this is the response to look at)
		certStatus:         string  &log  &optional;

		## thisUpdate
		thisUpdate:         string  &log  &optional;

		## nextUpdate
		nextUpdate:         string  &log  &optional;
		};
}

event ssl_stapled_ocsp(c: connection, is_orig: bool, response: string, status_type: count)
	{
	local resp: OCSP::Response = ocsp_parse_response(response);

	# TOCHECK: is this right?
	local resp_size: count =|response|;

	if (resp?$responses)
		{
		local num: count = 0;
		for (x in resp$responses)
			{
			num += 1;
			local single_resp: OCSP::SingleResp = resp$responses[x];
			local cert_id: OCSP::CertId = [$hashAlgorithm  = single_resp$hashAlgorithm,
			                               $issuerNameHash = single_resp$issuerNameHash,
				                       $issuerKeyHash  = single_resp$issuerKeyHash,
			                               $serialNumber   = single_resp$serialNumber];

			local resp_rec: Info = [$ts             = network_time(),
				                $status_type    = status_type,
						$cid            = c$id,
				                $cuid           = c$uid,
						$size           = resp_size,
						$responseStatus = resp$responseStatus,
						$responseType   = resp$responseType,
						$version        = resp$version,
						$responderID    = resp$responderID,
						$producedAt     = resp$producedAt,
						$idx            = num,
						$cert_id        = cert_id,
						$certStatus     = single_resp$certStatus,
						$thisUpdate     = single_resp$thisUpdate];

			if (single_resp?$nextUpdate)
				resp_rec$nextUpdate = single_resp$nextUpdate;
			Log::write(LOG, resp_rec);
			}
		}
	else
		{
                # no response content? this is weird but log it anyway
		local resp_rec_empty: Info = [$ts             = network_time(),
			                      $status_type    = status_type,
			                      $cid            = c$id,
					      $cuid           = c$uid,
			                      $size           = resp_size,
			                      $responseStatus = resp$responseStatus,
					      $responseType   = resp$responseType,
					      $version        = resp$version,
					      $responderID    = resp$responderID,
					      $producedAt     = resp$producedAt];
		Log::write(LOG, resp_rec_empty);
		}
	}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="ocsp-stapling"]);
	}
