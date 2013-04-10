##! File extraction support for FTP.

@load ./main
@load base/utils/files

module FTP;

export {
	## Pattern of file mime types to extract from FTP transfers.
	const extract_file_types = /NO_DEFAULT/ &redef;

	## The on-disk prefix for files to be extracted from FTP-data transfers.
	const extraction_prefix = "ftp-item" &redef;
}

global extract_count: count = 0;

redef record Info += {
	## On disk file where it was extracted to.
	extraction_file:       string &log &optional;
	
	## Indicates if the current command/response pair should attempt to 
	## extract the file if a file was transferred.
	extract_file:          bool &default=F;
};

event file_new(f: fa_file) &priority=5
	{
	if ( ! f?$source ) return;
	if ( f$source != "FTP_DATA" ) return;
	if ( ! f?$conns ) return;

	local fname: string = fmt("%s-%s-%d.dat", extraction_prefix, f$id,
	                          extract_count);
	local extracting: bool = F;

	for ( cid in f$conns )
		{
		local c: connection = f$conns[cid];

		if ( [cid$resp_h, cid$resp_p] !in ftp_data_expected ) next;

		local s = ftp_data_expected[cid$resp_h, cid$resp_p];

		if ( ! s$extract_file ) next;

		if ( ! extracting )
			{
			FileAnalysis::add_action(f, [$act=FileAnalysis::ACTION_EXTRACT,
			                             $extract_filename=fname]);
			extracting = T;
			++extract_count;
			}
		}
	}

event file_type(f: fa_file) &priority=5
	{
	if ( ! f?$mime_type ) return;
	if ( ! f?$source ) return;
	if ( f$source != "FTP_DATA" ) return;
	if ( extract_file_types !in f$mime_type ) return;

	if ( f?$info && FileAnalysis::ACTION_EXTRACT in f$info$actions_taken )
		return;

	local fname: string = fmt("%s-%s-%d.dat", extraction_prefix, f$id,
	                          extract_count);
	++extract_count;
	FileAnalysis::add_action(f, [$act=FileAnalysis::ACTION_EXTRACT,
	                             $extract_filename=fname]);
	}

event file_state_remove(f: fa_file) &priority=4
	{
	if ( ! f?$source ) return;
	if ( f$source != "FTP_DATA" ) return;
	if ( ! f?$info ) return;

	for ( filename in f$info$extracted_files )
		{
		local s: FTP::Info;
		s$ts = network_time();
		s$tags = set();
		s$user = "<ftp-data>";
		s$extraction_file = filename;

		if ( f?$conns )
			for ( cid in f$conns )
				{
				s$uid = f$conns[cid]$uid;
				s$id = cid;
				}

		Log::write(FTP::LOG, s);
		}
	}

event log_ftp(rec: Info) &priority=-10
	{
	delete rec$extraction_file;
	delete rec$extract_file;
	}
