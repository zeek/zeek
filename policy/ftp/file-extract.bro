##! File extraction for FTP.

@load ftp/base

module FTP;

export {
	## Pattern of file mime types to extract from HTTP entity bodies.
	const extract_file_types = /NO_DEFAULT/ &redef;

	## The on-disk prefix for files to be extracted from FTP-data transfers.
	const extraction_prefix = "ftp-item" &redef;
}

redef record State += {
	extracted_filename:   string &log &optional;
	
	extract_file:         bool &default=F;
};

redef enum Tags += { EXTRACTED_FILE };

event file_transferred(c: connection, prefix: string, descr: string,
			mime_type: string) &priority=3
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] !in ftp_data_expected )
		return;
		
	local expected = ftp_data_expected[id$resp_h, id$resp_p];
	local s = expected$state;

	if ( extract_file_types in s$mime_type )
		s$extract_file = T;
	
	if ( s$extract_file )
		{
		add s$tags[EXTRACTED_FILE];
		s$extracted_filename = fmt("%s.%s", extraction_prefix, id_string(c$id));
		}
	}

event file_transferred(c: connection, prefix: string, descr: string,
			mime_type: string) &priority=-4
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] !in ftp_data_expected )
		return;
		
	local expected = ftp_data_expected[id$resp_h, id$resp_p];
	local s = expected$state;
	
	if ( s$extract_file && s?$extracted_filename )
		{
		local fh = open(s$extracted_filename);
		if ( s$passive )
			set_contents_file(id, CONTENTS_RESP, fh);
		else
			set_contents_file(id, CONTENTS_ORIG, fh);
		}
	}

event log_ftp(rec: State) &priority=-10
	{
	delete rec$extracted_filename;
	delete rec$extract_file;
	}