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

function get_extraction_name(f: fa_file): string
	{
	local r = fmt("%s-%s.dat", extraction_prefix, f$id);
	return r;
	}

event file_new(f: fa_file) &priority=5
	{
	if ( ! f?$source ) return;
	if ( f$source != "HTTP" ) return;
	if ( ! f?$conns ) return;

	local fname: string;
	local c: connection;

	if ( f?$mime_type && extract_file_types in f$mime_type )
		{
		fname = get_extraction_name(f);
		FileAnalysis::add_analyzer(f, [$tag=FileAnalysis::ANALYZER_EXTRACT,
		                               $extract_filename=fname]);

		for ( cid in f$conns )
			{
			c = f$conns[cid];
			if ( ! c?$http ) next;
			c$http$extraction_file = fname;
			}

		return;
		}

	local extracting: bool = F;

	for ( cid in f$conns )
		{
		c = f$conns[cid];

		if ( ! c?$http ) next;

		if ( ! c$http$extract_file ) next;

		fname = get_extraction_name(f);
		FileAnalysis::add_analyzer(f, [$tag=FileAnalysis::ANALYZER_EXTRACT,
		                               $extract_filename=fname]);
		extracting = T;
		break;
		}

	if ( extracting )
		for ( cid in f$conns )
			{
			c = f$conns[cid];
			if ( ! c?$http ) next;
			c$http$extraction_file = fname;
			}
	}
