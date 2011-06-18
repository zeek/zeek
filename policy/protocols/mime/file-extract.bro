@load mime/file-ident
@load utils/files

module MIME;

export {
	## Pattern of file mime types to extract from MIME bodies.
	const extract_file_types = /NO_DEFAULT/ &redef;

	## The on-disk prefix for files to be extracted from MIME entity bodies.
	const extraction_prefix = "mime-item" &redef;

	redef record Info += {
		## Optionally write the file to disk.  Must be set prior to first 
		## data chunk being seen in an event.
		extract_file:         bool    &default=F;
	
		## Store the file handle here for the file currently being extracted.
		extraction_file:      file    &optional;
		
		## Store a count of the number of files that have been transferred in
		## this conversation to create unique file names on disk.
		num_extracted_files:  count   &optional;
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
		local suffix = fmt("%d.dat", ++c$mime$num_extracted_files);
		local fname = generate_extraction_filename(extraction_prefix, c, suffix);
		c$mime$extraction_file = open(fname);
		enable_raw_output(c$mime$extraction_file);
		}
	}
	
event mime_segment_data(c: connection, length: count, data: string) &priority=-5
	{
	if ( c$mime$extract_file && c$mime?$extraction_file )
		print c$mime$extraction_file, data;
	}
	
event mime_end_entity(c: connection) &priority=-3
	{
	# TODO: this check is only due to a bug in mime_end_entity that
	#       causes the event to be generated twice for the same real event.
	if ( ! c?$mime )
		return;
		
	if ( c$mime?$extraction_file )
		close(c$mime$extraction_file);
	}
	