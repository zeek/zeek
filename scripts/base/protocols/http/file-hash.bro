##! Calculate hashes for HTTP body transfers.

@load ./file-ident

module HTTP;

export {
	redef enum Notice::Type += {
		## Indicates that an MD5 sum was calculated for an HTTP response body.
		MD5,
	};

	redef record Info += {
		## MD5 sum for a file transferred over HTTP calculated from the 
		## response body.
		md5:             string   &log &optional;
		
		## This value can be set per-transfer to determine per request
		## if a file should have an MD5 sum generated.  It must be
		## set to T at the time of or before the first chunk of body data.
		calc_md5:        bool     &default=F;
		
		## Indicates if an MD5 sum is being calculated for the current 
		## request/response pair.
		calculating_md5: bool     &default=F;
	};
	
	## Generate MD5 sums for these filetypes.
	const generate_md5 = /application\/x-dosexec/    # Windows and DOS executables
	                   | /application\/x-executable/ # *NIX executable binary
	                   &redef;
}

## Initialize and calculate the hash.
event http_entity_data(c: connection, is_orig: bool, length: count, data: string) &priority=5
	{
	if ( is_orig || ! c?$http ) return;
	
	if ( c$http$first_chunk )
		{
		if ( c$http$calc_md5 || 
		     (c$http?$mime_type && generate_md5 in c$http$mime_type) )
			{
			c$http$calculating_md5 = T;
			md5_hash_init(c$id);
			}
		}
	
	if ( c$http$calculating_md5 )
		md5_hash_update(c$id, data);
	}
	
## In the event of a content gap during a file transfer, detect the state for
## the MD5 sum calculation and stop calculating the MD5 since it would be 
## incorrect anyway.
event content_gap(c: connection, is_orig: bool, seq: count, length: count) &priority=5
	{
	if ( is_orig || ! c?$http || ! c$http$calculating_md5 ) return;
	
	set_state(c, F, is_orig);
	c$http$calculating_md5 = F;
	md5_hash_finish(c$id);
	}

## When the file finishes downloading, finish the hash and generate a notice.
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority=-3
	{
	if ( is_orig || ! c?$http ) return;
	
	if ( c$http$calculating_md5 )
		{
		local url = build_url_http(c$http);
		c$http$calculating_md5 = F;
		c$http$md5 = md5_hash_finish(c$id);
		
		NOTICE([$note=MD5, $msg=fmt("%s %s %s", c$id$orig_h, c$http$md5, url),
		        $sub=c$http$md5, $conn=c, $URL=url]);
		}
	}

event connection_state_remove(c: connection) &priority=-5
	{
	if ( c?$http_state && 
	     c$http_state$current_response in c$http_state$pending &&
	     c$http_state$pending[c$http_state$current_response]$calculating_md5 )
		{
		# The MD5 sum isn't going to be saved anywhere since the entire 
		# body wouldn't have been seen anyway and we'd just be giving an
		# incorrect MD5 sum.
		md5_hash_finish(c$id);
		}
	}
