##! Utilities specific for HTTP processing.

@load ./main

module HTTP;

export {
	global extract_keys: function(data: string, kv_splitter: pattern): string_vec;
	global build_url: function(h: Info): string;
	global build_url_http: function(h: Info): string;
}


function extract_keys(data: string, kv_splitter: pattern): string_vec
	{
	local key_vec: vector of string = vector();
	
	local parts = split(data, kv_splitter);
	for ( part_index in parts )
		{
		local key_val = split1(parts[part_index], /=/);
		if ( 1 in key_val )
			key_vec[|key_vec|] = key_val[1];
		}
	return key_vec;
	}

function build_url(h: Info): string
	{
	local uri  = h?$uri ? h$uri : "/<missed_request>";
	local host = h?$host ? h$host : fmt("%s", h$id$resp_h);
	if ( h$id$resp_p != 80/tcp )
		host = fmt("%s:%s", host, h$id$resp_p);
	return fmt("%s%s", host, uri);
	}
	
function build_url_http(h: Info): string
	{
	return fmt("http://%s", build_url(h));
	}
