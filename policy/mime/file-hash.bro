@load mime/file-ident

module MIME;

export {
	## Pattern of file mime types to calculate MD5 sums for MIME bodies.
	const calc_md5_file_types = /NO_DEFAULT/ &redef;

	redef record Info += {
		## Optionally calculate the file's MD5 sum.  Must be set prior to the 
		## first data chunk being see in an event.
		calc_md5:         bool    &default=F;

		## The calculated MD5 sum for the MIME entity.
		md5_hash:         string  &log &optional;
	};
}

event mime_segment_data(c: connection, length: count, data: string) &priority=5
	{
	if ( calc_md5_file_types in c$mime$mime_type ) 
		c$mime$calc_md5 = T;
	}

event mime_segment_data(c: connection, length: count, data: string) &priority=3
	{
	if ( c$mime$calc_md5 )
		{
		if ( c$mime$content_len == 0 )
			md5_hash_init(c$id);
			
		md5_hash_update(c$id, data);
		}
	}
	
event mime_end_entity(c: connection) &priority=-3
	{
	if ( c$mime$calc_md5 )
		c$mime$md5_hash = md5_hash_finish(c$id);
	}