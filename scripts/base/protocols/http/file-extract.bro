##! Extracts the items from HTTP traffic, one per file.  At this time only 
##! the message body from the server can be extracted with this script.

@load ./main
@load ./file-analysis

module HTTP;

export {
	## Pattern of file mime types to extract from HTTP response entity bodies.
	const extract_file_types = /NO_DEFAULT/ &redef;

	## The on-disk prefix for files to be extracted from HTTP entity bodies.
	const extraction_prefix = "http-item" &redef;

	redef record Info += {
		## On-disk file where the response body was extracted to.
		extraction_file:  string &log &optional;
		
		## Indicates if the response body is to be extracted or not.  Must be 
		## set before or by the first :bro:see:`file_new` for the file content.
		extract_file:     bool &default=F;
	};
}

global extract_count: count = 0;

event file_type(f: fa_file) &priority=5
	{
	if ( ! f?$mime_type ) return;
	if ( ! f?$source ) return;
	if ( f$source != "HTTP" ) return;
	if ( extract_file_types !in f$mime_type ) return;

	if ( f?$info && FileAnalysis::ACTION_EXTRACT in f$info$actions_taken )
		return;

	local fname: string = fmt("%s-%s-%d.dat", extraction_prefix, f$id,
	                          extract_count);
	++extract_count;
	FileAnalysis::add_action(f, [$act=FileAnalysis::ACTION_EXTRACT,
	                             $extract_filename=fname]);

	if ( ! f?$conns ) return;

	for ( cid in f$conns )
		{
		local c: connection = f$conns[cid];

		if ( ! c?$http ) next;

		c$http$extraction_file = fname;
		}
	}

event file_new(f: fa_file) &priority=5
	{
	if ( ! f?$source ) return;
	if ( f$source != "HTTP" ) return;
	if ( ! f?$conns ) return;

	local fname: string = fmt("%s-%s-%d.dat", extraction_prefix, f$id,
	                          extract_count);
	local extracting: bool = F;

	for ( cid in f$conns )
		{
		local c: connection = f$conns[cid];

		if ( ! c?$http ) next;

		if ( c$http$extract_file )
			{
			if ( ! extracting )
				{
				FileAnalysis::add_action(f, [$act=FileAnalysis::ACTION_EXTRACT,
		                                     $extract_filename=fname]);
				extracting = T;
				++extract_count;
				}

			c$http$extraction_file = fname;
			}
		}
	}
