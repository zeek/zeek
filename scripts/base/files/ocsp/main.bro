@load base/frameworks/files
@load base/utils/paths
@load base/utils/queue

module OCSP;

export {
	## add one more argument to tell ocsp response or request
	redef record Files::AnalyzerArgs += {
		ocsp_type: string &optional;
	};

        ## ocsp logging
	redef enum Log::ID += { LOG };

	## type for pending ocsp request
	type PendingRequests: table[OCSP::CertId] of Queue::Queue;

	## NOTE: one file could contain several requests
	## one ocsp request record
	type Info_req: record {
		## time for the request
	        ts:                 time;
		## file id for this request
		id:                 string  &log;
		## version
		version:            count   &log &optional;
		## requestor name
		requestorName:      string  &log &optional;
		## NOTE: the above are for one file which may contain
		##       several ocsp requests
		## request cert id
		certId:             OCSP::CertId &optional;
	};

	## NOTE: one file could contain several response
	## one ocsp response record
	type Info_resp: record {
		## time for the response
	        ts:                 time;
		## file id for this response
		id:                 string  &log;
		## responseStatus (different from cert status?)
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
		##       the above are for one file which may contain
		##       several responses
		##cert id
		certId:             OCSP::CertId  &optional;
		## certStatus (this is the response to look at)
		certStatus:         string  &log  &optional;
		## thisUpdate
		thisUpdate:         string  &log  &optional;
		## nextUpdate
		nextUpdate:         string  &log  &optional;
	};

	type Info: record {
		## timestamp for request if a corresponding request is present
		## OR timestamp for response if a corresponding request is not found
		ts:                 time    &log;
		certId:             OCSP::CertId  &log  &optional;
		req:                Info_req      &log  &optional;
		resp:               Info_resp     &log  &optional;
	};

        ## Event for accessing logged OCSP records.
	global log_ocsp: event(rec: Info);
}

redef record connection += {
	## keep track of pending requests received so for
	ocsp_requests: PendingRequests &optional;
	};

event bro_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info, $ev=log_ocsp, $path="ocsp"]);
	}

function get_http_info(f: fa_file, meta: fa_metadata)
	{
	if (f$source != "HTTP" || !meta?$mime_type)
		return;

	# call OCSP file analyzer
	if (meta$mime_type == "application/ocsp-request")
		Files::add_analyzer(f, Files::ANALYZER_OCSP, [$ocsp_type = "request"]);
	else if (meta$mime_type == "application/ocsp-response")
		Files::add_analyzer(f, Files::ANALYZER_OCSP, [$ocsp_type = "response"]);
	}

event file_sniff(f: fa_file, meta: fa_metadata) &priority = 5
	{
	if (f$source == "HTTP")
		get_http_info(f, meta);
	}

event ocsp_request(f: fa_file, req_ref: opaque of ocsp_req, req: OCSP::Request) &priority = 5
	{
	local conn: connection;
	local cid: conn_id;

	# there should be only one loop: one connection
	for (id in f$conns)
		{
		cid = id;
		conn = f$conns[id];
		}

	if (req?$requestList)
		{
		for (x in req$requestList)
			{
			local one_req = req$requestList[x];
			local cert_id: OCSP::CertId = [$hashAlgorithm  = one_req$hashAlgorithm,
						       $issuerNameHash = one_req$issuerNameHash,
						       $issuerKeyHash  = one_req$issuerKeyHash,
						       $serialNumber   = one_req$serialNumber];

			local req_rec: Info_req = [$ts=network_time(), $id=f$id, $certId=cert_id];

			if (req?$version)
				req_rec$version = req$version;

			if (req?$requestorName)
				req_rec$requestorName = req$requestorName;

			if (!conn?$ocsp_requests)
				conn$ocsp_requests = table();

			if (cert_id !in conn$ocsp_requests)
				conn$ocsp_requests[cert_id] = Queue::init();

			Queue::put(conn$ocsp_requests[cert_id], req_rec);
			}
		}
	else
		{
		# no request content? this is weird but log it anyway
		local req_rec_empty: Info_req = [$ts=network_time(), $id=f$id];
		if (req?$version)
			req_rec_empty$version = req$version;
		if (req?$requestorName)
			req_rec_empty$requestorName = req$requestorName;
		Log::write(LOG, [$ts=req_rec_empty$ts, $req=req_rec_empty]);
		}
	}

event ocsp_response(f: fa_file, resp_ref: opaque of ocsp_resp, resp: OCSP::Response) &priority = 5
	{
	local conn: connection;
	local cid: conn_id;

	# there should be only one loop
	for (id in f$conns)
		{
		cid = id;
		conn = f$conns[id];
		}

	if (resp?$responses)
		{
		for (x in resp$responses)
			{
			local single_resp: OCSP::SingleResp = resp$responses[x];
			local cert_id: OCSP::CertId = [$hashAlgorithm  = single_resp$hashAlgorithm,
						       $issuerNameHash = single_resp$issuerNameHash,
						       $issuerKeyHash  = single_resp$issuerKeyHash,
						       $serialNumber   = single_resp$serialNumber];
			local resp_rec: Info_resp = [$ts = network_time(), $id = f$id,
						     $responseStatus = resp$responseStatus,
						     $responseType   = resp$responseType,
						     $version        = resp$version,
						     $responderID    = resp$responderID,
						     $producedAt     = resp$producedAt,
						     $certId         = cert_id,
						     $certStatus     = single_resp$certStatus,
						     $thisUpdate     = single_resp$thisUpdate];
			if (single_resp?$nextUpdate)
				resp_rec$nextUpdate = single_resp$nextUpdate;

			if (conn?$ocsp_requests && cert_id in conn$ocsp_requests)
				{
				# find a match
				local req_rec: Info_req = Queue::get(conn$ocsp_requests[cert_id]);
				Log::write(LOG, [$ts=req_rec$ts, $certId=req_rec$certId, $req=req_rec, $resp=resp_rec]);
				if (Queue::len(conn$ocsp_requests[cert_id]) == 0)
					delete conn$ocsp_requests[cert_id]; #if queue is empty, delete it?
				}
			else
				{
				# do not find a match; this is weird but log it
				Log::write(LOG, [$ts=resp_rec$ts, $certId=resp_rec$certId, $resp=resp_rec]);
				}
			}
		}
	else
		{
                # no response content? this is weird but log it anyway
		local resp_rec_empty: Info_resp = [$ts=network_time(), $id=f$id,
						   $responseStatus = resp$responseStatus,
						   $responseType   = resp$responseType,
						   $version        = resp$version,
						   $responderID    = resp$responderID,
						   $producedAt     = resp$producedAt];
		Log::write(LOG, [$ts=resp_rec_empty$ts, $resp=resp_rec_empty]);
		}
	}

function log_unmatched_msgs_queue(q: Queue::Queue)
	{
	local reqs: vector of Info_req;
	Queue::get_vector(q, reqs);

	for ( i in reqs )
		Log::write(LOG, [$ts=reqs[i]$ts, $certId=reqs[i]$certId, $req=reqs[i]]);
	}

function log_unmatched_msgs(msgs: PendingRequests)
	{
	for ( cert_id in msgs )
		log_unmatched_msgs_queue(msgs[cert_id]);

	clear_table(msgs);
	}

# need to log unmatched ocsp request if any
event connection_state_remove(c: connection) &priority= -5
	{
	if (! c?$ocsp_requests)
		return;
	log_unmatched_msgs(c$ocsp_requests);
	}
