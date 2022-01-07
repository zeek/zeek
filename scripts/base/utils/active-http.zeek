##! A module for performing active HTTP requests and
##! getting the reply at runtime.

@load ./exec

module ActiveHTTP;

export {
	## The default timeout for HTTP requests.
	option default_max_time = 1min;

	## The default HTTP method/verb to use for requests.
	option default_method = "GET";

	type Response: record {
		## Numeric response code from the server.
		code:      count;
		## String response message from the server.
		msg:       string;
		## Full body of the response.
		body:      string                  &optional;
		## All headers returned by the server.
		headers:   table[string] of string &optional;
	};

	type Request: record {
		## The URL being requested.
		url:             string;
		## The HTTP method/verb to use for the request.
		method:          string                  &default=default_method;
		## Data to send to the server in the client body.  Keep in
		## mind that you will probably need to set the *method* field
		## to "POST" or "PUT".
		client_data:     string                  &optional;

		# Arbitrary headers to pass to the server.  Some headers
		# will be included by libCurl.
		#custom_headers: table[string] of string &optional;

		## Timeout for the request.
		max_time:        interval                &default=default_max_time;
		## Additional curl command line arguments.  Be very careful
		## with this option since shell injection could take place
		## if careful handling of untrusted data is not applied.
		addl_curl_args:  string                  &optional;
	};

	## Perform an HTTP request according to the
	## :zeek:type:`ActiveHTTP::Request` record.  This is an asynchronous
	## function and must be called within a "when" statement.
	##
	## req: A record instance representing all options for an HTTP request.
	##
	## Returns: A record with the full response message.
	global request: function(req: ActiveHTTP::Request): ActiveHTTP::Response;
}

function request2curl(r: Request, bodyfile: string, headersfile: string): string
	{
	local cmd = fmt("curl -s -g -o %s -D %s -X %s",
	                safe_shell_quote(bodyfile),
	                safe_shell_quote(headersfile),
	                safe_shell_quote(r$method));

	cmd = fmt("%s -m %.0f", cmd, r$max_time);

	if ( r?$client_data )
		cmd = fmt("%s -d @-", cmd);

	if ( r?$addl_curl_args )
		cmd = fmt("%s %s", cmd, r$addl_curl_args);

	cmd = fmt("%s %s", cmd, safe_shell_quote(r$url));
	# Make sure file will exist even if curl did not write one.
	cmd = fmt("%s && touch %s", cmd, safe_shell_quote(bodyfile));
	return cmd;
	}

function request(req: Request): ActiveHTTP::Response
	{
	local resp: Response;
	resp$code = 0;
	resp$msg = "";
	resp$body = "";
	resp$headers = table();

	# Sanity-check the method parameter as it will go directly into our command line.
	if ( req$method != /[A-Za-z]+/ )
		{
		Reporter::error(fmt("There was an illegal method specified with ActiveHTTP (\"%s\").", req$method));
		return resp;
		}

	local tmpfile     = "/tmp/zeek-activehttp-" + unique_id("");
	local bodyfile    = fmt("%s_body", tmpfile);
	local headersfile = fmt("%s_headers", tmpfile);

	local cmd = request2curl(req, bodyfile, headersfile);
	local stdin_data = req?$client_data ? req$client_data : "";

	return when [req, resp, cmd, stdin_data, bodyfile, headersfile] ( local result = Exec::run([$cmd=cmd, $stdin=stdin_data, $read_files=set(bodyfile, headersfile)]) )
		{
		# If there is no response line then nothing else will work either.
		if ( ! (result?$files && headersfile in result$files) )
			{
			Reporter::error(fmt("There was a failure when requesting \"%s\" with ActiveHTTP.", req$url));
			return resp;
			}

		local headers = result$files[headersfile];
		for ( i in headers )
			{
			# The reply is the first line.
			if ( i == 0 )
				{
				local response_line = split_string_n(headers[0], /[[:blank:]]+/, F, 2);
				if ( |response_line| != 3 )
					return resp;

				resp$code = to_count(response_line[1]);
				resp$msg = response_line[2];
				resp$body = join_string_vec(result$files[bodyfile], "");
				}
			else
				{
				local line = headers[i];
				local h = split_string1(line, /:/);
				if ( |h| != 2 )
					next;
				resp$headers[h[0]] = sub_bytes(h[1], 0, |h[1]|-1);
				}
			}
		return resp;
		}
	}
