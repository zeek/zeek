@load mime/file-ident

module MIME;

export {
	## Pattern of file mime types to extract from MIME bodies.
	const extract_file_types = /NO_DEFAULT/ &redef;

	## The on-disk prefix for files to be extracted from HTTP entity bodies.
	const extraction_prefix = "mime-item" &redef;

	redef record Info += {
		## The name of the file where this MIME entity is written.
		on_disk_filename: string &optional &log;
		
		## Optionally write the file to disk.  Must be set prior to first 
		## data chunk being seen in an event.
		extract_file:     bool    &default=F;
	
		## Store the file handle here for the file currently being extracted.
		file_handle:      file    &optional;
	};
}

event mime_segment_data(c: connection, length: count, data: string) &priority=5
	{
	if ( extract_file_types in c$mime$mime_type ) 
		c$mime$extract_file = T;
	}

event mime_segment_data(c: connection, length: count, data: string) &priority=3
	{
	if ( c$mime$extract_file && c$mime$content_len == 0 )
		{
		c$mime$on_disk_filename = fmt("%s.%s-%d", extraction_prefix,
		                                          id_string(c$id),
		                                          c$mime_state$level);
		c$mime$file_handle = open(c$mime$on_disk_filename);
		enable_raw_output(c$mime$file_handle);
		}
	}
	
event mime_segment_data(c: connection, length: count, data: string) &priority=-5
	{
	if ( c$mime$extract_file && c$mime?$file_handle )
		print c$mime$file_handle, data;
	}
	
event mime_end_entity(c: connection) &priority=-5
	{
	if ( c$mime?$file_handle )
		close(c$mime$file_handle);
	}
	