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
		## set before or by the first :bro:enum:`FileAnalysis::TRIGGER_NEW`
		## for the file content.
		extract_file:     bool &default=F;
	};
}

global extract_count: count = 0;

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, info: FileAnalysis::Info)
	&priority=5
	{
	if ( trig != FileAnalysis::TRIGGER_TYPE ) return;
	if ( ! info?$mime_type ) return;
	if ( ! info?$source ) return;
	if ( info$source != "HTTP" ) return;
	if ( extract_file_types !in info$mime_type ) return;

	for ( act in info$actions )
		if ( act$act == FileAnalysis::ACTION_EXTRACT ) return;

	local fname: string = fmt("%s-%s-%d.dat", extraction_prefix, info$file_id,
	                          extract_count);
	++extract_count;
	FileAnalysis::add_action(info$file_id, [$act=FileAnalysis::ACTION_EXTRACT,
	                                        $extract_filename=fname]);

	if ( ! info?$conns ) return;

	for ( cid in info$conns )
		{
		local c: connection = info$conns[cid];

		if ( ! c?$http ) next;

		c$http$extraction_file = fname;
		}
	}

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, info: FileAnalysis::Info)
	&priority=5
	{
	if ( trig != FileAnalysis::TRIGGER_NEW ) return;
	if ( ! info?$source ) return;
	if ( info$source != "HTTP" ) return;
	if ( ! info?$conns ) return;

	local fname: string = fmt("%s-%s-%d.dat", extraction_prefix, info$file_id,
	                          extract_count);
	local extracting: bool = F;

	for ( cid in info$conns )
		{
		local c: connection = info$conns[cid];

		if ( ! c?$http ) next;

		if ( c$http$extract_file )
			{
			if ( ! extracting )
				{
				FileAnalysis::add_action(info$file_id,
				                         [$act=FileAnalysis::ACTION_EXTRACT,
		                                  $extract_filename=fname]);
				extracting = T;
				++extract_count;
				}

			c$http$extraction_file = fname;
			}
		}
	}
