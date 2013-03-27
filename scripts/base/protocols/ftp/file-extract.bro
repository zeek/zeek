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

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, info: FileAnalysis::Info)
	&priority=5
	{
	if ( trig != FileAnalysis::TRIGGER_NEW ) return;
	if ( ! info?$source ) return;
	if ( info$source != "FTP_DATA" ) return;
	if ( ! info?$conns ) return;

	local fname: string = fmt("%s-%s-%d.dat", extraction_prefix, info$file_id,
	                          extract_count);
	local extracting: bool = F;

	for ( cid in info$conns )
		{
		local c: connection = info$conns[cid];

		if ( [cid$resp_h, cid$resp_p] !in ftp_data_expected ) next;

		local s = ftp_data_expected[cid$resp_h, cid$resp_p];

		if ( ! s$extract_file ) next;

		if ( ! extracting )
			{
			FileAnalysis::add_action(info$file_id,
			                         [$act=FileAnalysis::ACTION_EXTRACT,
			                          $extract_filename=fname]);
			extracting = T;
			++extract_count;
			}
		}
	}

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, info: FileAnalysis::Info)
	&priority=5
	{
	if ( trig != FileAnalysis::TRIGGER_TYPE ) return;
	if ( ! info?$mime_type ) return;
	if ( ! info?$source ) return;
	if ( info$source != "FTP_DATA" ) return;
	if ( extract_file_types !in info$mime_type ) return;

	for ( act in info$actions )
		if ( act$act == FileAnalysis::ACTION_EXTRACT ) return;

	local fname: string = fmt("%s-%s-%d.dat", extraction_prefix, info$file_id,
	                          extract_count);
	++extract_count;
	FileAnalysis::add_action(info$file_id, [$act=FileAnalysis::ACTION_EXTRACT,
	                                        $extract_filename=fname]);
	}

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, info: FileAnalysis::Info)
	&priority=5
	{
	if ( trig != FileAnalysis::TRIGGER_EOF &&
	     trig != FileAnalysis::TRIGGER_DONE ) return;
	if ( ! info?$source ) return;
	if ( info$source != "FTP_DATA" ) return;

	for ( act in info$actions )
		if ( act$act == FileAnalysis::ACTION_EXTRACT )
			{
			local s: FTP::Info;
			s$ts = network_time();
			s$tags = set();
			s$user = "<ftp-data>";
			s$extraction_file = act$extract_filename;

			if ( info?$conns )
				for ( cid in info$conns )
					{
					s$uid = info$conns[cid]$uid;
					s$id = cid;
					break;
					}

			Log::write(FTP::LOG, s);
			}
	}

event log_ftp(rec: Info) &priority=-10
	{
	delete rec$extraction_file;
	delete rec$extract_file;
	}
