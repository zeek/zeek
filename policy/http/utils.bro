##! Utilities specific for HTTP processing.

@load http/base

module HTTP;

export {
	global extract_keys: function(data: string, kv_splitter: pattern): string_vec;
	global build_url: function(c: connection): string;
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

function build_url(c: connection): string
	{
	local host = c$http?$host ? c$http$host : fmt("%s",c$id$resp_h);
	return fmt("http://%s/%s", host, c$http$uri);
	}