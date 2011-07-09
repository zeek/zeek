@load protocols/mime/file-ident

module MIME;

export {
	redef enum Notice::Type += {
		## Indicates that an MD5 sum was calculated for a MIME message.
		MD5,
	};
	
	redef record Info += {	
		## The calculated MD5 sum for the MIME entity.
		md5:             string  &log &optional;
		
		## Optionally calculate the file's MD5 sum.  Must be set prior to the 
		## first data chunk being see in an event.
		calc_md5:        bool    &default=F;
		
		## This boolean value indicates if an MD5 sum is being calculated 
		## for the current file transfer.
		calculating_md5: bool    &default=F;
	};
	
	## Generate MD5 sums for these filetypes.
	const generate_md5 = /application\/x-dosexec/    # Windows and DOS executables
	                   | /application\/x-executable/ # *NIX executable binary
	                   &redef;
}

event mime_segment_data(c: connection, length: count, data: string) &priority=-5
	{
	if ( ! c?$mime ) return;
	
	if ( c$mime$content_len == 0 )
		{
		if ( generate_md5 in c$mime$mime_type )
			c$mime$calc_md5 = T;
		
		if ( c$mime$calc_md5 )
			{
			c$mime$calculating_md5 = T;
			md5_hash_init(c$id);
			}
		}
	
	if ( c$mime$calculating_md5 )
		md5_hash_update(c$id, data);
	}
	
## In the event of a content gap during the MIME transfer, detect the state for
## the MD5 sum calculation and stop calculating the MD5 since it would be 
## incorrect anyway.
event content_gap(c: connection, is_orig: bool, seq: count, length: count) &priority=5
	{
	if ( is_orig || ! c?$mime ) return;

	if ( c$mime$calculating_md5 )
		{
		c$mime$calculating_md5 = F;
		md5_hash_finish(c$id);
		}
	}
	
event mime_end_entity(c: connection) &priority=-3
	{
	# TODO: this check is only due to a bug in mime_end_entity that
	#       causes the event to be generated twice for the same real event.
	if ( ! c?$mime )
		return;
	
	if ( c$mime$calculating_md5 )
		{
		c$mime$md5 = md5_hash_finish(c$id);
		
		NOTICE([$note=MD5, $msg=fmt("Calculated a hash for a MIME entity from %s", c$id$orig_h),
		        $sub=c$mime$md5, $conn=c]);
		}
	}