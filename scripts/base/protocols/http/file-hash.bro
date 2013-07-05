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

event file_new(f: fa_file) &priority=5
	{
	if ( ! f?$source ) return;
	if ( f$source != "HTTP" ) return;

	if ( f?$mime_type && generate_md5 in f$mime_type )
		{
		FileAnalysis::add_analyzer(f, [$tag=FileAnalysis::ANALYZER_MD5]);
		return;
		}

	if ( ! f?$conns ) return;

	for ( cid in f$conns )
		{
		local c: connection = f$conns[cid];

		if ( ! c?$http ) next;

		if ( ! c$http$calc_md5 ) next;

		FileAnalysis::add_analyzer(f, [$tag=FileAnalysis::ANALYZER_MD5]);
		return;
		}
	}

event file_state_remove(f: fa_file) &priority=4
	{
	if ( ! f?$source ) return;
	if ( f$source != "HTTP" ) return;
	if ( ! f?$conns ) return;
	if ( ! f?$info ) return;
	if ( ! f$info?$md5 ) return;

	for ( cid in f$conns )
		{
		local c: connection = f$conns[cid];

		if ( ! c?$http ) next;

		c$http$md5 = f$info$md5;
		}
	}
