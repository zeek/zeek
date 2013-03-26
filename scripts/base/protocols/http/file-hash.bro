##! Calculate hashes for HTTP body transfers.

@load ./main
@load ./file-analysis

module HTTP;

export {
	redef record Info += {
		## MD5 sum for a file transferred over HTTP calculated from the 
		## response body.
		md5:             string     &log &optional;
		
		## This value can be set per-transfer to determine per request
		## if a file should have an MD5 sum generated.  It must be
		## set to T at the time of or before the first chunk of body data.
		calc_md5:        bool       &default=F;
	};
	
	## Generate MD5 sums for these filetypes.
	const generate_md5 = /application\/x-dosexec/    # Windows and DOS executables
	                   | /application\/x-executable/ # *NIX executable binary
	                   &redef;
}

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, info: FileAnalysis::Info)
	&priority=5
	{
	if ( trig != FileAnalysis::TRIGGER_TYPE ) return;
	if ( ! info?$mime_type ) return;
	if ( ! info?$source ) return;
	if ( info$source != "HTTP" ) return;

	if ( generate_md5 in info$mime_type )
		FileAnalysis::add_action(info$file_id, [$act=FileAnalysis::ACTION_MD5]);
	else if ( info?$conns )
		{
		for ( cid in info$conns )
			{
			local c: connection = info$conns[cid];

			if ( ! c?$http ) next;

			if ( c$http$calc_md5 )
				{
				FileAnalysis::add_action(info$file_id,
				                         [$act=FileAnalysis::ACTION_MD5]);
				return;
				}
			}
		}
	}

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, info: FileAnalysis::Info)
	&priority=5
	{
	if ( trig != FileAnalysis::TRIGGER_DONE &&
	     trig != FileAnalysis::TRIGGER_EOF ) return;
	if ( ! info?$source ) return;
	if ( info$source != "HTTP" ) return;
	if ( ! info?$conns ) return;

	local act: FileAnalysis::ActionArgs = [$act=FileAnalysis::ACTION_MD5];

	if ( act !in info$actions ) return;

	local result = info$actions[act];

	if ( ! result?$md5 ) return;

	for ( cid in info$conns )
		{
		local c: connection = info$conns[cid];

		if ( ! c?$http ) next;

		c$http$md5 = result$md5;
		}
	}

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, info: FileAnalysis::Info)
	&priority=5
	{
	if ( trig != FileAnalysis::TRIGGER_GAP ) return;
	if ( ! info?$source ) return;
	if ( info$source != "HTTP" ) return;

	FileAnalysis::remove_action(info$file_id, [$act=FileAnalysis::ACTION_MD5]);
	}
