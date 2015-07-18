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

	type Info_OCSP: record {
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

		## HTTP method
		method:         string     &log       &optional;

		## host in HTTP request + uri in HTTP request
		## last '/' is removed
		## for GET request, OCSP request is remove from url
		ocsp_uri:       string     &log       &optional;

		## number of HTTP requests containing ocsp requests in
		## this connection including this one; this may be
		## different from number of OCSP requests since one
		## HTTP request may contain several OCSP requests;
		## this is copied from connection
		num_ocsp:       count      &log       &optional;

		## the original_uri in HTTP request
		original_uri:   string     &log       &optional;		
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

	## connection used to get num_ocsp and connection start time
	conn:                     connection &optional;
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

event ocsp_response(f: fa_file, resp_ref: opaque of ocsp_resp, resp: OCSP::Response)
	{
        if ( ! f?$http )
		return;
        # check if there is a OCSP GET request
	if ( f$http?$method && f$http$method == "GET" )
		f$http$conn$num_ocsp += 1;
	}

event ocsp_request(f: fa_file, req_ref: opaque of ocsp_req, req: OCSP::Request)
	{
        if ( ! f?$http )
		return;
	f$http$conn$num_ocsp += 1;
	}

event http_reply (c: connection, version: string, code: count, reason: string)
	{
	if ( ! c?$http )
		return;
	if ( ! c$http?$conn )
		c$http$conn = c;
	}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
	{
	if ( ! c?$http )
		return;
	if ( ! c$http?$conn )
		c$http$conn = c;
	}

# record the header length
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
	{
	if ( ! c?$http )
		return;	
	if ( is_orig )
		c$http$request_header_len = stat$header_length;
	else
		c$http$response_header_len = stat$header_length;
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

function update_http_info(ocsp: OCSP_SSL_SPLIT::Info_OCSP, http: HTTP::Info)
	{
	ocsp$num_ocsp = http$conn$num_ocsp;

	if ( http?$method )
		ocsp$method = http$method;

	if ( http?$original_uri )
		ocsp$original_uri = http$original_uri;
	
	if ( http?$host )
		ocsp$ocsp_uri = http$host;

	if ( http?$uri )
		if ( ocsp?$ocsp_uri )
			ocsp$ocsp_uri += http$uri;
		else
			ocsp$ocsp_uri = http$uri;

	if ( http?$method && http$method == "GET" && http?$original_uri )
		{
		local uri_prefix: string = OCSP::get_uri_prefix(http$original_uri);
		if ( http?$host )
			ocsp$ocsp_uri = http$host;
		if ( |uri_prefix| > 0)
			ocsp$ocsp_uri += "/" + uri_prefix; 
		}

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

function start_log_ocsp(rec: OCSP::Info)
	{
	local http: HTTP::Info = rec$http;
	local info_ocsp_rec: OCSP_SSL_SPLIT::Info_OCSP = [$cid = http$id,
		                                          $cuid = http$uid,
							  $conn_start_ts = http$conn$start_time];

	if ( rec?$certId )
		info_ocsp_rec$cert_id = rec$certId;

	if ( rec?$req )
		{
		info_ocsp_rec$req = rec$req;
		info_ocsp_rec$req_ts = rec$req$ts;
		}

	if ( rec?$resp )
		{
		info_ocsp_rec$resp = rec$resp;
		info_ocsp_rec$resp_ts = rec$resp$ts;
		}

	if ( rec?$req && rec?$resp )
		info_ocsp_rec$delay = info_ocsp_rec$resp_ts - info_ocsp_rec$req_ts;

	update_http_info(info_ocsp_rec, http);
	Log::write(LOG_OCSP, info_ocsp_rec);
	}

# log OCSP information
event OCSP::log_ocsp(rec: OCSP::Info)
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

# convert all the elements in the queue to a formatted string
function convert_time_q2str(q: Queue::Queue, sep: string): string
	{
	local s = "";
	local elem: vector of time = vector();
	Queue::get_vector(q, elem);
	for ( i in elem )
		{
		s += fmt("%f",elem[i]);
		if ( i != (|elem| - 1))
			s += sep;
		}
	return s;
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
		local cert_recv_ts_str:string = convert_time_q2str(c$ssl$cert_ts[ocsp_uri, serial_number, issuer_name], ",");
		if (|cert_recv_ts_str| > 0)
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
