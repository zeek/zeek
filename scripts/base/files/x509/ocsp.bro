@load base/protocols/http
@load base/frameworks/files
@load base/utils/paths
@load base/utils/queue

# Note - this needs some cleaning up and is currently not loaded by default.

module OCSP;

export {
	## add one more argument to tell ocsp response or request
	redef record Files::AnalyzerArgs += {
		ocsp_type: string &optional;
	};

	## ocsp logging
	redef enum Log::ID += { LOG };

	## type for pending ocsp request
	type PendingQueue: table[OCSP::CertId] of Queue::Queue;

	## NOTE: one file could contain several requests
	## one ocsp request record
	type Info_req: record {
		## time for the request
		ts:                 time;
		## file id for this request or
		## hash of the GET url if it's GET request
		id:                 string  &log &optional;
		## connection id
		cid:                conn_id &optional;
		## connection uid
		cuid:               string  &optional;
		## version
		version:            count   &log &optional;
		## requestor name
		requestorName:      string  &log &optional;

		## NOTE: the above are for one file which may contain
		##       several ocsp requests

		## one OCSP request may contain several OCSP requests
		## with different cert id; this is the index of the
		## OCSP request with cert_id in the big OCSP request
		index:              count   &log &optional;
		## request cert id
		certId:             OCSP::CertId &optional;
		## HTTP method
		method:             string &optional;
	};

	## NOTE: one file could contain several response
	## one ocsp response record
	type Info_resp: record {
		## time for the response
	        ts:                 time;
		## file id for this response
		id:                 string  &log;
		## connection id
		cid:                conn_id &optional;
		## connection uid
		cuid:               string  &optional;
		## responseStatus (different from cert status?)
		responseStatus:     string  &log   &optional;
		## responseType
		responseType:       string  &log   &optional;
		## version
		version:            count   &log   &optional;
		## responderID
		responderID:        string  &log   &optional;
		## producedAt
		producedAt:         time    &log   &optional;
		## certificates
		certs:              vector of opaque of x509 &optional;

		## NOTE: the following are specific to one cert id
		##       the above are for one file which may contain
		##       several responses

		## one OCSP response may contain several OCSP responses
		## with different cert id; this is the index of the
		## OCSP response with cert_id in the big OCSP response
		index:              count   &log  &optional;
		##cert id
		certId:             OCSP::CertId  &optional;
		## certStatus (this is the response to look at)
		certStatus:         string  &log  &optional;
		## thisUpdate
		thisUpdate:         time    &log  &optional;
		## nextUpdate
		nextUpdate:         time    &log  &optional;
	};

	type Info: record {
		## timestamp for request if a corresponding request is present
		## OR timestamp for response if a corresponding request is not found
		ts:                 time          &log;

		## connection id
		cid:                conn_id       &log;

		## connection uid
		cuid:               string        &log;

		## cert id
		certId:             OCSP::CertId  &log  &optional;

		## request
		req:                Info_req      &log  &optional;

		## response timestamp
		resp_ts:            time          &log  &optional;

		## response
		resp:               Info_resp     &log  &optional;

		## HTTP method
		method:             string        &log  &optional;

		## HTTP record
		http:               HTTP::Info    &optional;
	};

        ## Event for accessing logged OCSP records.
	global log_ocsp: event(rec: Info);

        global get_uri_prefix: function(s: string): string;
}

redef record HTTP::Info += {
	# there should be one request and response but use Queue here
	# just in case
	ocsp_requests:            PendingQueue  &optional;
	ocsp_responses:           PendingQueue  &optional;

	current_content_type:     string        &optional &default="";
	original_uri:             string        &optional;

	# flag for checking get uri
	checked_get:              bool          &optional &default=F;

	# uri prefix: this the GET url without ocsp request
	uri_prefix:               string        &optional;
	};

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
	{
	c$http$original_uri = original_URI;
	}

event http_content_type(c: connection, is_orig: bool, ty: string, subty: string)
	{
	c$http$current_content_type = to_lower(ty + "/" + subty);
	}

function check_ocsp_file(f: fa_file, meta: fa_metadata)
	{
	if ( f$source != "HTTP" || ! f?$http )
		return;

	# call OCSP file analyzer
	if ( (meta?$mime_type && meta$mime_type == "application/ocsp-request") || f$http$current_content_type == "application/ocsp-request")
		{
		Files::add_analyzer(f, Files::ANALYZER_OCSP, [$ocsp_type = "request"]);
		}
	else if ( (meta?$mime_type && meta$mime_type == "application/ocsp-response") || f$http$current_content_type == "application/ocsp-response")
		{
		Files::add_analyzer(f, Files::ANALYZER_OCSP, [$ocsp_type = "response"]);
		}
	}

event file_sniff(f: fa_file, meta: fa_metadata) &priority = 5
	{
	if (f$source == "HTTP")
		check_ocsp_file(f, meta);
	}

function update_http_info(http: HTTP::Info, req_rec: OCSP::Info_req)
	{
	if ( http?$method )
		req_rec$method = http$method;
	}

function update_request_info(rec: Info_req, req: OCSP::Request)
	{
	if ( req?$version )
		rec$version = req$version;

	if ( req?$requestorName )
		rec$requestorName = req$requestorName;
	}

function cert_id_from_request(one_req: OCSP::OneReq): OCSP::CertId
	{
	local cert_id: OCSP::CertId = [];
	if ( one_req?$hashAlgorithm )
		cert_id$hashAlgorithm = one_req$hashAlgorithm;

	if ( one_req?$issuerNameHash )
		cert_id$issuerNameHash = one_req$issuerNameHash;

	if ( one_req?$issuerKeyHash )
		cert_id$issuerKeyHash = one_req$issuerKeyHash;

	if ( one_req?$serialNumber )
		cert_id$serialNumber = one_req$serialNumber;

	return cert_id;
	}

function enq_request(http: HTTP::Info, req: OCSP::Request, req_id: string, req_ts: time)
	{
	local index: count = 0;
	if ( req?$requestList && |req$requestList| > 0 )
		{
		index += 1;
		for (x in req$requestList)
			{
			local one_req = req$requestList[x];
			local cert_id: OCSP::CertId = cert_id_from_request(one_req);
			local req_rec: OCSP::Info_req = [$ts     = req_ts,
							 $certId = cert_id,
							 $cid    = http$id,
							 $cuid   = http$uid,
							 $index  = index,
							 $id     = req_id];
			update_request_info(req_rec, req);

			if ( ! http?$ocsp_requests )
				http$ocsp_requests = table();

			if ( cert_id !in http$ocsp_requests )
				http$ocsp_requests[cert_id] = Queue::init();

			update_http_info(http, req_rec);
			Queue::put(http$ocsp_requests[cert_id], req_rec);
			}
		}
	else if ( req?$version )
		{
		# it's ocsp request but has no request content
		# this is weird but log it anyway
		local req_rec_empty: OCSP::Info_req = [$ts   = req_ts,
			                               $cid  = http$id,
						       $cuid = http$uid,
						       $id   = req_id];
		update_request_info(req_rec_empty, req);
		update_http_info(http, req_rec_empty);
		Log::write(LOG, [$ts=req_rec_empty$ts, $req=req_rec_empty, $cid=http$id, $cuid=http$uid, $method=http$method, $http=http]);
		}
	}

event ocsp_request(f: fa_file, req_ref: opaque of ocsp_req, req: OCSP::Request) &priority = 5
	{
        if ( ! f?$http )
		return;
	enq_request(f$http, req, f$id, network_time());
	}

function get_first_slash(s: string): string
	{
	local s_len = |s|;
	if (s[0] == "/")
		return "/" + get_first_slash(s[1:s_len]);
	else
		return "";
	}

function remove_first_slash(s: string): string
	{
	local s_len = |s|;
	if (s[0] == "/")
		return remove_first_slash(s[1:s_len]);
	else
		return s;
	}

function get_uri_prefix(s: string): string
	{
	local uri_prefix = get_first_slash(s);
	local w = split_string(s[|uri_prefix|:], /\//);
	local i = 0;
	while ( i < (|w| - 1) )
		{
		uri_prefix += w[i] + "/";
		i += 1;
		}
	return uri_prefix;
	}

function check_ocsp_request_uri(http: HTTP::Info): OCSP::Request
	{
	local parsed_req: OCSP::Request;
	if ( ! http?$original_uri )
		return parsed_req;;
	local uri_prefix: string = get_uri_prefix(http$original_uri);
	http$uri_prefix = uri_prefix;
	local ocsp_req_str: string = http$uri[|uri_prefix|:];
	parsed_req = ocsp_parse_request(decode_base64(ocsp_req_str));
	if ( ! parsed_req?$requestList || |parsed_req$requestList| == 0 )
		{
		# normal parse fails, bug url, naively try each part
		local w = split_string(http$original_uri, /\//);
		local s = "";
		for ( i in w )
			{
			s += w[i] + "/";
			ocsp_req_str = http$uri[|s|:];
			parsed_req = ocsp_parse_request(decode_base64(ocsp_req_str));
			if ( parsed_req?$requestList && |parsed_req$requestList| > 0 )
				{
				http$uri_prefix = s;
				break;
				}
			}
		}
	return parsed_req;
	}

function update_response_info_single(rec: Info_resp, single_resp: OCSP::SingleResp)
	{
	if ( single_resp?$certStatus )
		rec$certStatus = single_resp$certStatus;

	if ( single_resp?$thisUpdate )
		rec$thisUpdate = single_resp$thisUpdate;

	if ( single_resp?$nextUpdate )
		rec$nextUpdate = single_resp$nextUpdate;
	}

function update_response_info(rec: Info_resp, resp: OCSP::Response)
	{
	if ( resp?$responseStatus )
		rec$responseStatus = resp$responseStatus;

	if ( resp?$responseType )
		rec$responseType = resp$responseType;

	if ( resp?$version )
		rec$version = resp$version;

	if ( resp?$responderID )
		rec$responderID = resp$responderID;

	if ( resp?$producedAt )
		rec$producedAt = resp$producedAt;

	if ( resp?$certs )
		rec$certs = resp$certs;
	}

function update_response_info_with_single(rec: Info_resp, resp: OCSP::Response, single_resp: OCSP::SingleResp)
	{
	update_response_info(rec, resp);
	update_response_info_single(rec, single_resp);
	}

function cert_id_from_response(single_resp: OCSP::SingleResp): OCSP::CertId
	{
	local cert_id: OCSP::CertId = [];
	if ( single_resp?$hashAlgorithm )
		cert_id$hashAlgorithm = single_resp$hashAlgorithm;

	if ( single_resp?$issuerNameHash )
		cert_id$issuerNameHash = single_resp$issuerNameHash;

	if ( single_resp?$issuerKeyHash )
		cert_id$issuerKeyHash = single_resp$issuerKeyHash;

	if ( single_resp?$serialNumber )
		cert_id$serialNumber = single_resp$serialNumber;

	return cert_id;
	}

event ocsp_response(f: fa_file, resp_ref: opaque of ocsp_resp, resp: OCSP::Response) &priority = 5
	{
	if ( ! f?$http )
		return;

	if ( resp?$responses && |resp$responses| > 0 )
		{
		local index: count = 0;
		for (x in resp$responses)
			{
			index += 1;
			local single_resp: OCSP::SingleResp = resp$responses[x];
			local cert_id: OCSP::CertId = cert_id_from_response(single_resp);
			local resp_rec: Info_resp = [$ts     = network_time(),
						     $id     = f$id,
						     $cid    = f$http$id,
						     $cuid   = f$http$uid,
						     $index  = index,
						     $certId = cert_id];
			update_response_info_with_single(resp_rec, resp, single_resp);

			if ( ! f$http?$ocsp_responses )
				f$http$ocsp_responses = table();

			if ( cert_id !in f$http$ocsp_responses )
				f$http$ocsp_responses[cert_id] = Queue::init();

			Queue::put(f$http$ocsp_responses[cert_id], resp_rec);
			}
		}
	else
		{
                # no response content? this is weird but log it anyway
		local resp_rec_empty: Info_resp = [$ts   = network_time(),
			                           $id   = f$id,
			                           $cid  = f$http$id,
						   $cuid = f$http$uid];
		update_response_info(resp_rec_empty, resp);
		local info_rec: Info = [$ts      = resp_rec_empty$ts,
					$resp_ts = resp_rec_empty$ts,
					$resp    = resp_rec_empty,
					$cid     = f$http$id,
					$cuid    = f$http$uid,
					$http    = f$http];
		if ( f$http?$method )
			info_rec$method = f$http$method;
		Log::write(LOG, info_rec);
		}

	# check if there is a OCSP GET request
	if ( f$http?$method && f$http$method == "GET" && ! f$http$checked_get )
		{
		f$http$checked_get = T;
		local req_get: OCSP::Request = check_ocsp_request_uri(f$http);
		enq_request(f$http, req_get, "H" + sha1_hash(f$http$original_uri), f$http$ts);
		}
	}

function log_unmatched_reqs_queue(q: Queue::Queue, http: HTTP::Info)
	{
	local reqs: vector of Info_req;
	Queue::get_vector(q, reqs);
	for ( i in reqs )
		{
		local info_rec: Info = [$ts     = reqs[i]$ts,
			                $certId = reqs[i]$certId,
					$req    = reqs[i],
					$cid    = reqs[i]$cid,
					$cuid   = reqs[i]$cuid,
					$http   = http];
		if ( reqs[i]?$method )
			info_rec$method = reqs[i]$method;
		Log::write(LOG, info_rec);
		}
	}

function log_unmatched_reqs(http: HTTP::Info)
	{
	local reqs: PendingQueue = http$ocsp_requests;
	for ( cert_id in reqs )
		log_unmatched_reqs_queue(reqs[cert_id], http);
	clear_table(reqs);
	}

function start_log_ocsp(http: HTTP::Info)
	{
	if ( ! http?$ocsp_requests && ! http?$ocsp_responses )
		return;

	if ( ! http?$ocsp_responses )
		{
		log_unmatched_reqs(http);
		return;
		}

	for ( cert_id in http$ocsp_responses )
		{
		while ( Queue::len(http$ocsp_responses[cert_id]) != 0 )
			{
			# have unmatched responses
			local resp_rec: Info_resp = Queue::get(http$ocsp_responses[cert_id]);
			local info_rec: Info = [$ts      = resp_rec$ts,
			                        $certId  = resp_rec$certId,
						$resp_ts = resp_rec$ts,
						$resp    = resp_rec,
						$cid     = http$id,
						$cuid    = http$uid,
						$http    = http];

			if ( http?$ocsp_requests && cert_id in http$ocsp_requests )
				{
				# find a match
				local req_rec: Info_req = Queue::get(http$ocsp_requests[cert_id]);
				info_rec$req = req_rec;
				info_rec$ts  = req_rec$ts;
				if (Queue::len(http$ocsp_requests[cert_id]) == 0)
					delete http$ocsp_requests[cert_id];
				}
			if ( http?$method )
				info_rec$method = http$method;
			Log::write(LOG, info_rec);
			}
		if ( Queue::len(http$ocsp_responses[cert_id]) == 0 )
			delete http$ocsp_responses[cert_id];
		}
	if ( http?$ocsp_requests && |http$ocsp_requests| != 0 )
		log_unmatched_reqs(http);
	}

# log OCSP information
event HTTP::log_http(rec: HTTP::Info)
	{
	start_log_ocsp(rec);
	}

event bro_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info, $ev=log_ocsp, $path="ocsp"]);
	}
