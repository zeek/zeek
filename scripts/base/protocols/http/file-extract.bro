##! Extracts the items from HTTP traffic, one per file.  At this time only 
##! the message body from the server can be extracted with this script.

@load ./main
@load ./file-ident
@load base/utils/files

module HTTP;

export {
	## Pattern of file mime types to extract from HTTP response entity bodies.
	const extract_file_types = /NO_DEFAULT/ &redef;

	## The on-disk prefix for files to be extracted from HTTP entity bodies.
	const extraction_prefix = "http-item" &redef;

	redef record Info += {
		## On-disk file where the response body was extracted to.
		extraction_file:  file &log &optional;
		
		## Indicates if the response body is to be extracted or not.  Must be 
		## set before or by the first :bro:id:`http_entity_data` event for the
		## content.
		extract_file:     bool &default=F;
	};
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string) &priority=-5
	{
	# Client body extraction is not currently supported in this script.
	if ( is_orig )
		return;
	
	if ( c$http$first_chunk )
		{
		if ( c$http?$mime_type &&
		     extract_file_types in c$http$mime_type )
			{
			c$http$extract_file = T;
			}
			
		if ( c$http$extract_file )
			{
			local suffix = fmt("%s_%d.dat", is_orig ? "orig" : "resp", c$http_state$current_response);
			local fname = generate_extraction_filename(extraction_prefix, c, suffix);
			
			c$http$extraction_file = open(fname);
			enable_raw_output(c$http$extraction_file);
			}
		}

	if ( c$http?$extraction_file )
		print c$http$extraction_file, data;
	}

event http_end_entity(c: connection, is_orig: bool)
	{
	if ( c$http?$extraction_file )
		close(c$http$extraction_file);
	}
