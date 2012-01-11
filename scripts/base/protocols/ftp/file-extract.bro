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

redef record Info += {
	## On disk file where it was extracted to.
	extraction_file:       file &log &optional;
	
	## Indicates if the current command/response pair should attempt to 
	## extract the file if a file was transferred.
	extract_file:          bool &default=F;
	
	## Internal tracking of the total number of files extracted during this 
	## session.
	num_extracted_files:   count &default=0;
};

event file_transferred(c: connection, prefix: string, descr: string,
			mime_type: string) &priority=3
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] !in ftp_data_expected )
		return;
		
	local s = ftp_data_expected[id$resp_h, id$resp_p];

	if ( extract_file_types in s$mime_type )
		{
		s$extract_file = T;
		++s$num_extracted_files;
		}
	}

event file_transferred(c: connection, prefix: string, descr: string,
			mime_type: string) &priority=-4
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] !in ftp_data_expected )
		return;
		
	local s = ftp_data_expected[id$resp_h, id$resp_p];
	
	if ( s$extract_file )
		{
		local suffix = fmt("%d.dat", s$num_extracted_files);
		local fname = generate_extraction_filename(extraction_prefix, c, suffix);
		s$extraction_file = open(fname);
		if ( s$passive )
			set_contents_file(id, CONTENTS_RESP, s$extraction_file);
		else
			set_contents_file(id, CONTENTS_ORIG, s$extraction_file);
		}
	}

event log_ftp(rec: Info) &priority=-10
	{
	delete rec$extraction_file;
	delete rec$extract_file;
	}
