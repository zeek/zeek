#! Match OCSP request and response to SSL connection for performance analysis

@load base/protocols/http
@load base/frameworks/files
@load base/files/x509
@load base/protocols/ssl
@load base/utils/queue

module OCSP_MEASUREMENT;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## cert id for the OCSP request
		cert_id:        OCSP::CertId      &log  &optional;

		## request timestamp
		req_ts:         time              &log  &optional;

		## request
		## NOTE: this is only one request if multiple requests
		## are sent together in one HTTP message, they will be
		## logged separately
		req:            OCSP::Info_req    &log  &optional;

		## response timestamp
		resp_ts:        time              &log  &optional;

		## response
		## NOTE: similar to request, if multiple responses are
		## sent together in one HTTP message, they will be
		## logged separately
		resp:           OCSP::Info_resp   &log  &optional;

		## HTTP connection uid
		cuid:            string     &log;

		## HTTP connection start time
		conn_start_ts:   time       &log;

		## for 1st request, this is the time between first TCP
		## SYN and resp_ts; for the rest of the requests in
		## the same connection, this is the time btween req_ts
		## and resp_ts
		delay:           interval   &log       &optional;

		## the size of HTTP request body
	        req_size:        count      &log       &optional;

		## the size of HTTP request header
		req_hdr_size:    count      &log       &optional;

		## the size of HTTP response body
		resp_size:       count      &log       &optional;

		## the size of HTTP response header
		resp_hdr_size:   count      &log       &optional;

		## the HTTP code in the HTTP response
		http_code:       count      &log       &optional;

		## OCSP host, this is host in HTTP request
		host:            string     &log;

		## OCSP uri, this is uri in HTTP request
		uri:             string     &log;

		## number of HTTP request containing ocsp requests in
		## this connection including this one; this may be
		## different from number of OCSP requests since one
		## HTTP request may contain several OCSP requests
		num_ocsp:        count      &log       &optional;

		## the time when the corresponding certificate is
                ## received
		cert_recv_ts:    time       &log       &optional;

		## SSL connection uid
		ssl_cuid:        string     &log       &optional;

		## SSL connection id
		ssl_cid:         conn_id               &optional;

		## the time when client receives change cipher message
		## from server
		ssl_change_cipher_ts:  time &log       &optional;

		## the time when SSL connection is established
		ssl_establish_ts:      time &log       &optional;
		};

	## - map to OCSP_MEASUREMENT::Info
	## - indexed by source ip(addr), ocsp uri(string), issuer name
	##   hash(string), serialNumber(string)
	## - is it possible server sends two same certificate? To be
	##   safe, let's use a queue to store OCSP_MEASUREMENT::Info
	type OCSP_Mapping: table[addr, string, string, string] of Queue::Queue &optional &read_expire=5mins;

	## a group of constant string for hash algorithm
	## to save memory, remove any unseen hash algorithm 
	global hash_algorithm = vector("sha1", "sha224", "sha256", "sha384", "sha512");

	## Event from a worker to the manager that it has encountered
        ## an OCSP response
	global new_ocsp_info: event(c: connection) &redef;

	## Event from the manager to the workers that a new OCSP info
	## is to be added.
        global ocsp_info_add: event(c: connection);
}

# by different hash algorithm, OCSP_Mapping
global ocsp_map: table[string] of OCSP_MEASUREMENT::OCSP_Mapping;

# track number of ocsp requests in this connection
redef record connection += {
	num_ocsp:  count                &optional &default=0;
	};

# add additional information to http info
redef record HTTP::Info += {
	## header length
	request_header_len:       count  &optional &default=0;
	response_header_len:      count  &optional &default=0;

	## OCSP file id
	ocsp_request_fuid:        string &optional;
	ocsp_response_fuid:       string &optional;

	## OCSP request and response timestamp
	ocsp_request_ts:          time   &optional;
	ocsp_response_ts:         time   &optional;

	## store OCSP requests and responses
	ocsp_request:   OCSP::Request    &optional;
	ocsp_response:  OCSP::Response   &optional;
};

# add additional information to ssl info
redef record SSL::Info += {
	## connection start time
	connection_start_ts:      time  &optional;

	## client hello time
	client_hello_ts:          time  &optional;

	## ssl connection establish time
	ssl_establish_ts:         time  &optional;

	## the time when server sends change-cipher-spec
	change_cipher_ts:         time  &optional;

	## - the time when a cert is received AND the cert has ocsp
        ##   extension
	## - the 2nd level table indexed by source ip(addr), ocsp
        ##   uri(string), issuer name hash(string), serialNumber
        ##   (string)
	## - the 1st level table indexed by different hash algorithm
        ##   for issuer name hash
	## - is it possible a server sends two same certificate? To be
	##   safe, let's use a queue to store the time
	cert_ts: table[string] of table[addr, string, string, string] of Queue::Queue &optional;
};

# set up cluster event
@if ( Cluster::is_enabled() )
@load base/frameworks/cluster
redef Cluster::manager2worker_events += /OCSP_MEASUREMENT::ocsp_info_add/;
redef Cluster::worker2manager_events += /OCSP_MEASUREMENT::new_ocsp_info/;
@endif

# get all the requests in one HTTP request
function get_all_requests(http: HTTP::Info): table[OCSP::CertId] of Queue::Queue
	{
	local pending_requests: table[OCSP::CertId] of Queue::Queue = table();
	if ( http?$ocsp_request && http$ocsp_request?$requestList )
		{
		local req = http$ocsp_request;
                for (x in req$requestList)
			{
			local one_req = req$requestList[x];
			local cert_id: OCSP::CertId = [$hashAlgorithm  = one_req$hashAlgorithm,
			                               $issuerNameHash = one_req$issuerNameHash,
			                               $issuerKeyHash  = one_req$issuerKeyHash,
			                               $serialNumber   = one_req$serialNumber];

		        local req_rec: OCSP::Info_req = [$ts=http$ocsp_request_ts, $id=http$ocsp_request_fuid, $certId=cert_id];

		        if (req?$version)
				req_rec$version = req$version;

			if (req?$requestorName)
				req_rec$requestorName = req$requestorName;

			if (cert_id !in pending_requests)
				pending_requests[cert_id] = Queue::init();
				
			Queue::put(pending_requests[cert_id], req_rec);
			}
		}	
	return pending_requests;
	}

# remove the last '/'
function clean_uri(s: string): string
	{
	local s_len = |s|;
	s_len -= 1;
	if (s[-1] == "/")
		return clean_uri(s[0:s_len]);
	else
		return s;
	}	

# fill in OCSP/HTTP information
function fill_ocsp_info(c: connection)
	{
	local http: HTTP::Info = c$http;
	
	# get all the requests which will be matched to response later
	local pending_requests: table[OCSP::CertId] of Queue::Queue = get_all_requests(http);

	# get all the responses and match them to the requests
	if ( http?$ocsp_response && http$ocsp_response?$responses )
		{
		local resp = http$ocsp_response;
                for (x in resp$responses)
			{
			local single_resp: OCSP::SingleResp = resp$responses[x];
			local cert_id: OCSP::CertId = [$hashAlgorithm  = single_resp$hashAlgorithm,
			                               $issuerNameHash = single_resp$issuerNameHash,
			                               $issuerKeyHash  = single_resp$issuerKeyHash,
			                               $serialNumber   = single_resp$serialNumber];

			local resp_rec: OCSP::Info_resp = [$ts             = http$ocsp_response_ts,
						           $id             = http$ocsp_response_fuid,
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

			local ocsp_info: OCSP_MEASUREMENT::Info = [$cert_id       = cert_id,
			                                           $cuid          = http$uid,
								   $conn_start_ts = c$start_time,
								   $host          = http$host,
				                                   $uri           = http$uri,
								   $resp_ts       = resp_rec$ts,
								   $resp          = resp_rec,
				                                   $req_size      = http$request_body_len,
								   $req_hdr_size  = http$request_header_len,
								   $resp_size     = http$response_body_len,
								   $resp_hdr_size = http$response_header_len,
								   $http_code     = http$status_code];
			if (cert_id in pending_requests)
				{
				# find a match
				local req_rec: OCSP::Info_req = Queue::get(pending_requests[cert_id]);
				ocsp_info$req      = req_rec;
				ocsp_info$req_ts   = req_rec$ts;
				ocsp_info$num_ocsp = c$num_ocsp;
				
				if (c$num_ocsp == 1)
					ocsp_info$delay = ocsp_info$resp$ts - c$start_time;
				else
					ocsp_info$delay = ocsp_info$resp$ts - ocsp_info$req$ts;

				if (Queue::len(pending_requests[cert_id]) == 0)
					delete pending_requests[cert_id]; #if queue is empty, delete it?
				}

			# add to ocsp map
			local full_uri: string = clean_uri(http$host + http$uri);
			local h = cert_id$hashAlgorithm;
			local src_ip: addr = c$id$orig_h;

			if ( [src_ip, full_uri, cert_id$issuerNameHash, cert_id$serialNumber] !in ocsp_map[h] )
				ocsp_map[h][src_ip, full_uri, cert_id$issuerNameHash, cert_id$serialNumber] = Queue::init();

			Queue::put(ocsp_map[h][src_ip, full_uri, cert_id$issuerNameHash, cert_id$serialNumber], ocsp_info);	
			}
		
		}
	}

# work event
@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
event OCSP_MEASUREMENT::ocsp_info_add(c: connection)
	{
	fill_ocsp_info(c);
	}
@endif

# manager event
@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
event OCSP_MEASUREMENT::new_ocsp_info(c: connection)
	{
	event OCSP_MEASUREMENT::ocsp_info_add(c);
	}
@endif

# record the header length
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
	{
	# proceed only this http connection has ocsp request or response
	if ( ! c$http?$ocsp_request && ! c$http?$ocsp_response )
		return;

	if ( is_orig )
		{
		c$http$request_header_len = stat$header_length;
		c$num_ocsp += 1;
		}
	else
		{
		c$http$response_header_len = stat$header_length;
		# here, a http request-response is done
		# if any ocsp info is present, put it in ocsp_map
@if ( ! Cluster::is_enabled() )
	        fill_ocsp_info(c);
@endif

@if ( Cluster::is_enabled() )
                # send this ocsp info to manager and manager will send
                # it to all the workder
                event OCSP_MEASUREMENT::new_ocsp_info(c);
@endif
		}
	}

# add ocsp request to http record
event ocsp_request(f: fa_file, req_ref: opaque of ocsp_req, req: OCSP::Request)
	{
	if ( !f?$http )
		return;
	f$http$ocsp_request = req;
	f$http$ocsp_request_ts = network_time();
	f$http$ocsp_request_fuid = f$id;
	}

# add ocsp response to http record
event ocsp_response(f: fa_file, resp_ref: opaque of ocsp_resp, resp: OCSP::Response)
	{
	if ( !f?$http )
		return;
	f$http$ocsp_response  = resp;
	f$http$ocsp_response_ts = network_time();
	f$http$ocsp_response_fuid = f$id;
	}

# add client hello time and connection start time
event ssl_client_hello(c: connection, version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec)
	{
	c$ssl$client_hello_ts = network_time();
	c$ssl$connection_start_ts = c$start_time;
	}

# add time stamp for server's change cipher message
event ssl_change_cipher_spec(c: connection, is_orig: bool)
	{
	if ( is_orig )
		return;
	c$ssl$change_cipher_ts = network_time();
	}

# add ssl established time
event ssl_established(c: connection)
	{
	c$ssl$ssl_establish_ts = network_time();
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
	if (!ext?$name || ext$name != "Authority Information Access")
		return;

	if ( !f?$info || !f$info?$x509 || !f$info$x509?$handle || !f$info$x509?$certificate)
		return;

	local ocsp_uri: string = clean_uri(get_ocsp_uri(ext$value));
	if ( |ocsp_uri| == 0 )
		return;
		
	local cert: X509::Certificate = f$info$x509$certificate;
	local serial_number: string = cert$serial;
	local cert_ref: opaque of x509 = f$info$x509$handle;

	# get connection
	local c: connection;
	# there should be only one loop
	for ( id in f$conns )
		c = f$conns[id];

	if ( !c$ssl?$cert_ts )
		c$ssl$cert_ts = table();
	
	local current_ts: time = network_time();
	local source_ip: addr = c$id$orig_h;

	local issuer_name: table[string] of string;
	# loop through each hash algorithm
	for (i in hash_algorithm)
		{
		local h: string = hash_algorithm[i];
		issuer_name[h] = x509_issuer_name_hash(cert_ref, h);

		# if given hash algorithm is not in record, create a new table
		if ( h !in c$ssl$cert_ts )
			c$ssl$cert_ts[h] = table();

		# if given index is not in record, create a new queue
		if ( [source_ip, ocsp_uri, issuer_name[h], serial_number] !in c$ssl$cert_ts[h] )
			c$ssl$cert_ts[h][source_ip, ocsp_uri, issuer_name[h], serial_number] = Queue::init();

		# put the timing information in the queue of ssl info
		Queue::put(c$ssl$cert_ts[h][source_ip, ocsp_uri, issuer_name[h], serial_number], current_ts);
		}
	}

# log information when ssl connection is removed
event connection_state_remove(c: connection) &priority= -20
	{
	if ( ! c?$ssl || ! c$ssl?$cert_ts )
		return;

	for (i in hash_algorithm)
		{
		local h = hash_algorithm[i];
		for ( [src_ip, ocsp_uri, issuer_name, serial_number] in c$ssl$cert_ts[h] )
			{
			if ( [src_ip, ocsp_uri, issuer_name, serial_number] in ocsp_map[h] )
				{
				# find a ocsp to ssl match
				local ocsp_info: OCSP_MEASUREMENT::Info = Queue::get(ocsp_map[h][src_ip, ocsp_uri, issuer_name, serial_number]);
				if (Queue::len(ocsp_map[h][src_ip, ocsp_uri, issuer_name, serial_number]) == 0)
					delete ocsp_map[h][src_ip, ocsp_uri, issuer_name, serial_number];
				local cert_recv_ts: time = Queue::get(c$ssl$cert_ts[h][src_ip, ocsp_uri, issuer_name, serial_number]);
				if (Queue::len(c$ssl$cert_ts[h][src_ip, ocsp_uri, issuer_name, serial_number]) == 0)
					delete c$ssl$cert_ts[h][src_ip, ocsp_uri, issuer_name, serial_number];
				ocsp_info$cert_recv_ts = cert_recv_ts;
				ocsp_info$ssl_cuid = c$uid;
				ocsp_info$ssl_cid = c$id;
				ocsp_info$ssl_change_cipher_ts = c$ssl$change_cipher_ts;
				ocsp_info$ssl_establish_ts = c$ssl$ssl_establish_ts;
				Log::write(LOG, ocsp_info);
				}
			}
		}
	}
		
event bro_init()
	{
	# initialize ocsp_map
	for (i in hash_algorithm)
		ocsp_map[hash_algorithm[i]] = table();
		
	Log::create_stream(LOG, [$columns=Info, $path="ocsp-measurement"]);
	}
