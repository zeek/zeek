#! log OCSP request, response and related HTTP information
#! log SSL connection which has cert with OCSP uri

@load base/protocols/http
@load base/frameworks/files
@load base/files/x509
@load base/protocols/ssl
@load base/utils/queue

module OCSP_SSL_SPLIT;

export {
	redef enum Log::ID += { LOG_OCSP };
	redef enum Log::ID += { LOG_SSL };

	type PendingRequests: table[OCSP::CertId] of Queue::Queue;
	
	type OCSP_Request_Type: record {
		ts:             time;
		fuid:           string;
		req:            OCSP::Request;
		};

	type OCSP_Response_Type: record {
		ts:             time;
		fuid:           string;
		resp:           OCSP::Response;
		};
	
	type Info_OCSP: record {
		## cert id for the OCSP request
		cert_id:        OCSP::CertId      &log  &optional;

		## request timestamp
		req_ts:         time              &log  &optional;

		## one OCSP request may contain several OCSP requests
                ## with different cert id; this is the index of the
                ## OCSP request with cert_id in the big OCSP request
		req_index:      count             &log  &optional;
		
		## request
		## NOTE: this is only one request if multiple requests
		## are sent together in one HTTP message, they will be
		## logged separately
		req:            OCSP::Info_req    &log  &optional;

		## response timestamp
		resp_ts:        time              &log  &optional;

		## one OCSP response may contain several OCSP responses
                ## with different cert id; this is the index of the
                ## OCSP response with cert_id in the big OCSP response
		resp_index:      count             &log  &optional;

		## response
		## NOTE: similar to request, if multiple responses are
		## sent together in one HTTP message, they will be
		## logged separately
		resp:           OCSP::Info_resp   &log  &optional;

		## HTTP connection id
		cid:            conn_id    &log;

		## HTTP connection uid
		cuid:           string     &log;

		## HTTP connection start time
		conn_start_ts:  time       &log;

		## the time between req_ts and resp_ts
		delay:          interval   &log       &optional;

		## the size of HTTP request body
	        req_size:       count      &log       &optional;

		## the size of HTTP request header
		req_hdr_size:   count      &log       &optional;

		## the size of HTTP response body
		resp_size:      count      &log       &optional;

		## the size of HTTP response header
		resp_hdr_size:  count      &log       &optional;

		## the HTTP code in the HTTP response
		http_code:      count      &log       &optional;

		## host in HTTP request + uri in HTTP request
		## last '/' is removed
		ocsp_uri:       string     &log       &optional;

		## number of HTTP requests containing ocsp requests in
		## this connection including this one; this may be
		## different from number of OCSP requests since one
		## HTTP request may contain several OCSP requests;
		## this is copied from connection
		num_ocsp:       count      &log       &optional;
		};

	type Issuer_Name_Type: record {
		sha1:              string     &log       &optional;
		sha224:            string     &log       &optional;
		sha256:            string     &log       &optional;
		sha384:            string     &log       &optional;
		sha512:            string     &log       &optional;
		};

	type Info_SSL: record {
		## connection id
		id:                conn_id    &log;

		## uid
		uid:               string     &log;

		## connection start time
		conn_start_ts:     time       &log       &optional;

		## client hello time
		client_hello_ts:   time       &log       &optional;

		## server hello time
		server_hello_ts:   time       &log       &optional;
		
		## the time for client change cipher message
		client_change_cipher_ts:  time       &log       &optional;

		## the time for server change cipher message
		server_change_cipher_ts:  time       &log       &optional;

		## the time when SSL connection is established
		establish_ts:      time       &log       &optional;

		## the time for the first encrypted application data
		client_first_encrypt_ts:   time       &log       &optional;
		
		## the time when event connection_state_remove happens
		end_ts:            time       &log       &optional;

		## the above are common information for SSL connection
		## the following is specific to an cert

		## ocsp_uri
		ocsp_uri:          string     &log       &optional;

		## serial_number
		serial_number:     string     &log       &optional;
		
		## the time when the corresponding certificate is
                ## received; formatted as: str(time),str(time)
		cert_recv_ts:      string     &log       &optional;
		
	        ## issuer_name
	        issuer_name:       Issuer_Name_Type     &log       &optional;
		};
}

redef SSL::disable_analyzer_after_detection=F;

redef record connection += {
	## track number of ocsp requests in this connection
	num_ocsp:  count                &optional &default=0;
	};

# add additional information to http info
redef record HTTP::Info += {
	## header length
	request_header_len:       count  &optional &default=0;
	response_header_len:      count  &optional &default=0;

	## OCSP_Request_Type
	ocsp_requests:            vector of OCSP_Request_Type  &optional;

	## OCSP_Response_Type
	ocsp_responses:           vector of OCSP_Response_Type &optional;

	## connection start time, copied from connection
	conn_start_ts:            time  &optional;

	## number of OCSP requests so far, copied from connection
	num_ocsp:                 count &optional;
};

# add additional information to ssl info
redef record SSL::Info += {
	## connection start time
	conn_start_ts:            time  &optional;

	## the time when client hello event happens
	client_hello_ts:          time  &optional;

	## server hello time
	server_hello_ts:          time  &optional;
	
	## the time when ssl connection is established
	establish_ts:             time  &optional;

	## the time for client change cipher message
	client_change_cipher_ts:  time  &optional;
	
	## the time for server change cipher message
	server_change_cipher_ts:  time  &optional;
	
	## indexed by ocsp_uri(string), serialNumber(string), issuer
	## name hash(string)
	cert_ts: table[string, string, OCSP_SSL_SPLIT::Issuer_Name_Type] of Queue::Queue &optional;

	## the time for the first encrypted application data
	client_first_encrypt_ts:          time  &optional;
};

# remove the last '/'
function clean_uri(s: string): string
	{
	local s_len = |s|;
	if ( s_len == 0 )
		return s;
	s_len -= 1;
	if (s[-1] == "/")
		return clean_uri(s[0:s_len]);
	else
		return s;
	}	

# record the header length and update num_ocsp and conn_start_ts
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
	{
	# proceed only this http connection has ocsp request or response
	if ( ! c$http?$ocsp_requests && ! c$http?$ocsp_responses )
		return;

	if ( is_orig )
		{
		c$http$request_header_len = stat$header_length;
		c$num_ocsp += 1;
		}
	else
		{
		c$http$response_header_len = stat$header_length;
		}
	c$http$num_ocsp = c$num_ocsp;
	c$http$conn_start_ts = c$start_time;
	}

# add ocsp request to http record
event ocsp_request(f: fa_file, req_ref: opaque of ocsp_req, req: OCSP::Request)
	{
	if ( ! f?$http )
		return;
	local request: OCSP_Request_Type = [$ts   = network_time(),
		                            $fuid = f$id,
					    $req  = req];
	if ( ! f$http?$ocsp_requests )
		f$http$ocsp_requests = vector();
	f$http$ocsp_requests[|f$http$ocsp_requests|] = request;
	}

# add ocsp response to http record
event ocsp_response(f: fa_file, resp_ref: opaque of ocsp_resp, resp: OCSP::Response)
	{
	if ( ! f?$http )
		return;
	local response: OCSP_Response_Type = [$ts   = network_time(),
		                              $fuid = f$id,
					      $resp = resp];
	if ( ! f$http?$ocsp_responses )
		f$http$ocsp_responses = vector();
	f$http$ocsp_responses[|f$http$ocsp_responses|] = response;
	}

# add server hello time
event ssl_server_hello(c: connection, version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count)&priority=5
	{
	c$ssl$server_hello_ts = network_time();
	}

# add client hello time and connection start time
event ssl_client_hello(c: connection, version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec)
	{
	c$ssl$client_hello_ts = network_time();
	c$ssl$conn_start_ts = c$start_time;
	}

# add time stamp for server's change cipher message
event ssl_change_cipher_spec(c: connection, is_orig: bool)
	{
	if ( is_orig )
		c$ssl$client_change_cipher_ts = network_time();
	else
		c$ssl$server_change_cipher_ts = network_time();
	}

# add ssl established time
event ssl_established(c: connection)
	{
	c$ssl$establish_ts = network_time();
	}

# add time when first encrypted application data is sent from client
event ssl_encrypted_data(c: connection, is_orig: bool, content_type: count, length: count)
	{
	if ( ! c?$ssl )
		return;
		
	if ( content_type == SSL::APPLICATION_DATA && length > 0 && is_orig && ! c$ssl?$client_first_encrypt_ts )
		c$ssl$client_first_encrypt_ts = network_time();
	}

# extract the full ocsp uri from certificate extension
function get_ocsp_uri(s: string): string
	{
	s = strip(s);
	s = to_lower(s);
	local parts = split_string(s, /\x0a/);
	for (x in parts)
		{
		local f4c = sub_bytes(parts[x], 0, 4);
		if (f4c == "ocsp")
			{
			local w = split_string(parts[x], /\/\//);
			return w[1];
			}
		}
	return "";
	}

# create ocsp index if ocsp extension is encountered
# record the time when certificate is received
event x509_extension(f: fa_file, ext: X509::Extension) &priority= -10 {
	if ( ! ext?$name || ext$name != "Authority Information Access")
		return;

	if ( ! f?$info || ! f$info?$x509 || ! f$info$x509?$handle || ! f$info$x509?$certificate)
		return;

	local ocsp_uri: string = clean_uri(get_ocsp_uri(ext$value));
	if ( |ocsp_uri| == 0 )
		return;
		
	local cert: X509::Certificate = f$info$x509$certificate;
	local serial_number: string = cert$serial;
	local cert_ref: opaque of x509 = f$info$x509$handle;

	# get connection TODO:TOCHECK
	local c: connection;
	# there should be only one loop?
	for ( id in f$conns )
		c = f$conns[id];

	if ( ! c$ssl?$cert_ts )
		c$ssl$cert_ts = table();
	
	local current_ts: time = network_time();
		
	local issuer_name: Issuer_Name_Type;
	issuer_name$sha1 = x509_issuer_name_hash(cert_ref, "sha1");
	issuer_name$sha224 = x509_issuer_name_hash(cert_ref, "sha224");
	issuer_name$sha256 = x509_issuer_name_hash(cert_ref, "sha256");
	issuer_name$sha384 = x509_issuer_name_hash(cert_ref, "sha384");
	issuer_name$sha512 = x509_issuer_name_hash(cert_ref, "sha512");

	# if given index is not in record, create a new queue
	if ( [ocsp_uri, serial_number, issuer_name] !in c$ssl$cert_ts )
		c$ssl$cert_ts[ocsp_uri, serial_number, issuer_name] = Queue::init();
		
	# put the timing information in the queue
	Queue::put(c$ssl$cert_ts[ocsp_uri, serial_number, issuer_name], current_ts);
	}

# log unmatched ocsp request or response
function log_unmatched_ocsp_queue (q: Queue::Queue)
	{
	local rec: vector of OCSP_SSL_SPLIT::Info_OCSP;
	Queue::get_vector(q, rec);
	for ( i in rec )
		Log::write(LOG_OCSP, rec[i]);
	}

# log unmatched ocsp request or response
function log_unmatched_ocsp(ocsp: table[OCSP::CertId] of Queue::Queue)
	{
	for ( cert_id in ocsp )
		log_unmatched_ocsp_queue(ocsp[cert_id]);
	clear_table(ocsp);
	}

# update http data in ocsp info record
function update_http_info(ocsp: OCSP_SSL_SPLIT::Info_OCSP, http: HTTP::Info)
	{
	if ( http?$host )
		ocsp$ocsp_uri = http$host;

	if ( http?$uri )
		if ( ocsp?$ocsp_uri )
			ocsp$ocsp_uri += http$uri;
		else
			ocsp$ocsp_uri = http$uri;

	if ( ocsp?$ocsp_uri )
		ocsp$ocsp_uri = clean_uri(ocsp$ocsp_uri);

	if ( http?$status_code )
		ocsp$http_code = http$status_code;
		
	if ( http?$request_body_len )
		ocsp$req_size = http$request_body_len;

	if ( http?$request_header_len )
		ocsp$req_hdr_size = http$request_header_len;	

	if ( http?$response_body_len )
		ocsp$resp_size = http$response_body_len;

	if ( http?$response_header_len )
		ocsp$resp_hdr_size = http$response_header_len;
	}

# get all the ocsp requests
function get_ocsp_requests(http: HTTP::Info): PendingRequests
	{
	local pending_ocsp_requests: PendingRequests = table();

	if ( ! http?$ocsp_requests )
		return pending_ocsp_requests;
		
	for ( x in http$ocsp_requests )
		{
		local request: OCSP_Request_Type = http$ocsp_requests[x];
		if ( ! request?$req )
			next;
			
		local req: OCSP::Request = request$req;
		if ( ! req?$requestList )
			next;
			
		local req_index: count = 0;
		for ( y in req$requestList )
			{
			req_index += 1;
			local one_req = req$requestList[y];
			local cert_id: OCSP::CertId = [$hashAlgorithm  = one_req$hashAlgorithm,
			                               $issuerNameHash = one_req$issuerNameHash,
			                               $issuerKeyHash  = one_req$issuerKeyHash,
			                               $serialNumber   = one_req$serialNumber];

		        local req_rec: OCSP::Info_req = [$ts=request$ts, $id=request$fuid, $certId=cert_id];

		        if (req?$version)
				req_rec$version = req$version;

			if (req?$requestorName)
				req_rec$requestorName = req$requestorName;

			local ocsp_info_rec: OCSP_SSL_SPLIT::Info_OCSP = [$cert_id       = cert_id,
				                                          $req_ts        = request$ts,
									  $req_index     = req_index,
									  $req           = req_rec,
									  $cid           = http$id,
									  $cuid          = http$uid,
									  $conn_start_ts = http$conn_start_ts,
									  $num_ocsp      = http$num_ocsp];
			update_http_info(ocsp_info_rec, http);

			if ( cert_id !in pending_ocsp_requests )
				pending_ocsp_requests[cert_id] = Queue::init();

			Queue::put(pending_ocsp_requests[cert_id], ocsp_info_rec);
			}
		}
	return pending_ocsp_requests;
	}

# log OCSP
function start_log_ocsp(http: HTTP::Info)
	{
	if ( ! http?$ocsp_requests && ! http?$ocsp_responses )
		return;
		
	local pending_ocsp_requests: PendingRequests = get_ocsp_requests(http);
	
	if ( ! http?$ocsp_responses )
		{
		log_unmatched_ocsp(pending_ocsp_requests);
		return;
		}
	
	for ( x in http$ocsp_responses )
		{
                local response: OCSP_Response_Type = http$ocsp_responses[x];
		if ( ! response?$resp )
			next;

		local resp: OCSP::Response = response$resp;
		if ( ! resp?$responses )
			next;

		local resp_index: count = 0;
		for ( y in resp$responses )
			{
			resp_index += 1;
			local single_resp: OCSP::SingleResp = resp$responses[y];
			local cert_id: OCSP::CertId = [$hashAlgorithm  = single_resp$hashAlgorithm,
			                               $issuerNameHash = single_resp$issuerNameHash,
			                               $issuerKeyHash  = single_resp$issuerKeyHash,
			                               $serialNumber   = single_resp$serialNumber];

			local resp_rec: OCSP::Info_resp = [$ts             = response$ts,
						           $id             = response$fuid,
							   $responseStatus = resp$responseStatus,
							   $responseType   = resp$responseType,
							   $version        = resp$version,
							   $responderID    = resp$responderID,
							   $producedAt     = resp$producedAt,
							   $certId         = cert_id,
							   $certStatus     = single_resp$certStatus,
							   $thisUpdate     = single_resp$thisUpdate];
			if ( single_resp?$nextUpdate )
				resp_rec$nextUpdate = single_resp$nextUpdate;

			if ( cert_id in pending_ocsp_requests)
				{
				# find a match
				local ocsp_info: OCSP_SSL_SPLIT::Info_OCSP = Queue::get(pending_ocsp_requests[cert_id]);
				ocsp_info$resp       = resp_rec;
				ocsp_info$resp_ts    = response$ts;
				ocsp_info$resp_index = resp_index;

				# update http info, previously filled in fill_ocsp_request
				update_http_info(ocsp_info, http);
				
				ocsp_info$delay = ocsp_info$resp$ts - ocsp_info$req$ts;

				if (Queue::len(pending_ocsp_requests[cert_id]) == 0)
					delete pending_ocsp_requests[cert_id];

				Log::write(LOG_OCSP, ocsp_info);
				}
			else
				{
				local ocsp_info_noreq: OCSP_SSL_SPLIT::Info_OCSP = [$cert_id       = cert_id,
					                                            $resp_ts       = resp_rec$ts,
										    $resp_index    = resp_index,
										    $resp          = resp_rec,
										    $cid           = http$id,
										    $cuid          = http$uid,
										    $conn_start_ts = http$conn_start_ts,
										    $num_ocsp      = http$num_ocsp];
				update_http_info(ocsp_info_noreq, http);
				Log::write(LOG_OCSP, ocsp_info_noreq);
				}
			}
		}
	if ( |pending_ocsp_requests| != 0 )
		log_unmatched_ocsp(pending_ocsp_requests);
	}

# log OCSP information
event HTTP::log_http(rec: HTTP::Info)
	{
	start_log_ocsp(rec);
	}

# update ssl info
function update_ssl_info(ssl_rec: OCSP_SSL_SPLIT::Info_SSL, ssl: SSL::Info)
	{
	if ( ssl?$conn_start_ts )
		ssl_rec$conn_start_ts = ssl$conn_start_ts;

	if ( ssl?$client_hello_ts )
		ssl_rec$client_hello_ts = ssl$client_hello_ts;

	if ( ssl?$client_first_encrypt_ts )
		ssl_rec$client_first_encrypt_ts = ssl$client_first_encrypt_ts;

	if ( ssl?$server_hello_ts )
		ssl_rec$server_hello_ts = ssl$server_hello_ts;

	if ( ssl?$establish_ts )
		ssl_rec$establish_ts = ssl$establish_ts;

	if ( ssl?$client_change_cipher_ts )
		ssl_rec$client_change_cipher_ts = ssl$client_change_cipher_ts;

	if ( ssl?$server_change_cipher_ts )
		ssl_rec$server_change_cipher_ts = ssl$server_change_cipher_ts;
	}

# log SSL information when ssl connection is removed
event connection_state_remove(c: connection) &priority= -20
	{
	if ( ! c?$ssl || ! c$ssl?$cert_ts )
		return;
		
	for ( [ocsp_uri, serial_number, issuer_name] in c$ssl$cert_ts )
		{
		local ssl_info_rec: OCSP_SSL_SPLIT::Info_SSL = [$id     = c$id,
		                                                $uid    = c$uid,
								$end_ts = network_time()];
		
		ssl_info_rec$ocsp_uri      = ocsp_uri;
		ssl_info_rec$serial_number = serial_number;
		ssl_info_rec$issuer_name   = issuer_name;

		# convert all the elements in the queue to a formatted string
		local cert_recv_ts_str: string = "";
		local elem: vector of time;
		Queue::get_vector(c$ssl$cert_ts[ocsp_uri, serial_number, issuer_name], elem);
		for ( i in elem )
			{
			cert_recv_ts_str += fmt("%f",elem[i]);
			if ( i != (|elem| - 1))
				cert_recv_ts_str += ",";
			}
		ssl_info_rec$cert_recv_ts = cert_recv_ts_str;
		update_ssl_info(ssl_info_rec, c$ssl);
		Log::write(LOG_SSL, ssl_info_rec);
		#delete c$ssl$cert_ts[ocsp_uri, serial_number, issuer_name];
		}
	clear_table(c$ssl$cert_ts);		
	}
		
event bro_init()
	{
	Log::create_stream(LOG_OCSP, [$columns=Info_OCSP, $path="ocsp-to-match"]);
	Log::create_stream(LOG_SSL, [$columns=Info_SSL, $path="ssl-to-match"]);
	}
