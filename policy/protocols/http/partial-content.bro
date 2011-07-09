##! This script makes it possible for the HTTP analysis scripts to analyze
##! the apparent normal case of "206 Partial Content" responses.

@load notice

module HTTP;

export {
	redef enum Notice::Type += {
		Partial_Content_Out_Of_Order,
	};
	
	type Range: record {
		from: count;
		to:   count;
	} &log;

	redef record Info += {
		current_range:   count           &default=0;
		request_ranges:  vector of Range &optional;
		response_range:  Range           &optional;
	};
	
	## Index is client IP address, server IP address, and URL being requested.  The
	## URL is tracked as part of the index in case multiple partial content segmented
	## files are being transferred simultaneously between the server and client.
	global partial_content_files: table[addr, addr, string] of Info &read_expire=5mins &redef;
}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=2
	{
	local parts: table[count] of string;
	if ( is_orig && name == "RANGE" )
		{
		# Example --> Range: bytes=1-1,2336-4951
		parts = split(value, /[=]/);
		if ( 2 in parts )
			{
			local ranges = split(parts[2], /,/);
			for ( i in ranges )
				{
				if ( ! c$http?$request_ranges )
					c$http$request_ranges = vector();
				parts = split(ranges[i], /-/);
				local r: Range = [$from=extract_count(parts[1]), $to=extract_count(parts[2])];
				print r;
				c$http$request_ranges[|c$http$request_ranges|] = r;
				}
			}
		}
	else if ( ! is_orig && name == "CONTENT-RANGE" )
		{
		# Example --> Content-Range: bytes 2336-4951/489528
		parts = split(value, /[0-9]*/);
		
		c$http$response_range = [$from=extract_count(parts[2]), $to=extract_count(parts[4])];
		
		}
	}
	
event http_reply(c: connection, version: string, code: count, reason: string) &priority=5
	{
	if ( code != 206 || ! c$http?$request_ranges )
		return;

	local url = build_url(c$http);
	if ( [c$id$orig_h, c$id$resp_h, url] !in partial_content_files )
		{
		partial_content_files[c$id$orig_h, c$id$resp_h, url] = copy(c$http);
		}
	}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
	{
	if ( is_orig || c$http$status_code != 206 || ! c$http?$request_ranges )
		return;
	
	local url = build_url(c$http);
	local http = partial_content_files[c$id$orig_h, c$id$resp_h, url];
	local range = http$request_ranges[http$current_range];
	
	print http$current_range;
	if ( http$current_range == 0 &&
	     c$http$response_range$from == 0 )
		{
		print "correct file beginning!";
		}
	}

event http_end_entity(c: connection, is_orig: bool)
	{
	print "end entity";
	++c$http$current_range;
	}
