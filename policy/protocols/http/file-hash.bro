##! Calculate hashes for HTTP body transfers.

@load http/file-ident
@load notice

module HTTP;

export {
	redef enum Notice::Type += {
		## Indicates an MD5 sum in Team Cymru's Malware Hash Registry.  
		## http://www.team-cymru.org/Services/MHR/
		HTTP_MHR_Malware,
	};

	redef record Info += {
		## The MD5 sum for a file transferred over HTTP will be stored here.
		md5:             string   &log &optional;
		
		## This value can be set per-transfer to determine per request
		## if a file should have an MD5 sum generated.  It must be
		## set to T at the time of or before the first chunk of body data.
		calc_md5:        bool &default=F;
		
		## This boolean value indicates if an MD5 sum is being calculated 
		## for the current file transfer.
		calculating_md5: bool &default=F;
	};
	
	## Generate MD5 sums for these filetypes.
	const generate_md5 = /application\/x-dosexec/    # Windows and DOS executables
	                   | /application\/x-executable/ &redef; # *NIX executable binary
}


# Once a file that we're interested has begun downloading, initialize
# an MD5 hash.
event file_transferred(c: connection, prefix: string, descr: string, mime_type: string) &priority=5
	{
	if ( ! c?$http ) return;
	
	if ( (generate_md5 in mime_type || c$http$calc_md5 ) && 
		 ! c$http$calculating_md5 )
		{
		c$http$calculating_md5 = T;
		md5_hash_init(c$id);
		}
	}

# As the file downloads, continue building the hash.
event http_entity_data(c: connection, is_orig: bool, length: count, data: string) &priority=-5
	{
	if ( is_orig ) return;
	
	if ( c$http$calculating_md5 )
		md5_hash_update(c$id, data);
	}
	
# When the file finishes downloading, finish the hash, check for the hash
# in the MHR, and raise a notice if the hash is there.
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority=-4
	{
	if ( is_orig || ! c?$http ) return;
	
	if ( c$http$calculating_md5 )
		{
		local url = build_url(c$http);
		c$http$calculating_md5 = F;
		c$http$md5 = md5_hash_finish(c$id);
				
		local hash_domain = fmt("%s.malware.hash.cymru.com", c$http$md5);
		when ( local addrs = lookup_hostname(hash_domain) )
			{
			# 127.0.0.2 indicates that the md5 sum was found in the MHR.
			if ( 127.0.0.2 in addrs )
				{
				local message = fmt("%s %s %s", c$id$orig_h, c$http$md5, url);
				NOTICE([$note=HTTP_MHR_Malware, $msg=message, $conn=c,
				        $method=c$http$method, $URL=url]);
				}
			}
		}
	}

event connection_state_remove(c: connection) &priority=-5
	{
	if ( c?$http && c$http$calculating_md5 )
		md5_hash_finish(c$id);
	}
