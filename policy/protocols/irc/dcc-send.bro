##! File extraction and introspection for DCC transfers over IRC.
##!
##! There is a major problem with this script in the cluster context because
##! we might see A send B a message that a DCC connection is to be expected,
##! but that connection will actually be between B and C which could be 
##! analyzed on a different worker.
##!
##! Example line from IRC server indicating that the DCC SEND is about to start:
##!    PRIVMSG my_nick :^ADCC SEND whateverfile.zip 3640061780 1026 41709^A

@load irc/base

module IRC;

export {
	redef enum Tag += { EXTRACTED_FILE };

	## Pattern of file mime types to extract from IRC DCC file transfers.
	const extract_file_types = /NO_DEFAULT/ &redef;

	## The on-disk prefix for files to be extracted from IRC DCC file transfers.
	const extraction_prefix = "irc-dcc-item" &redef;

	redef record Info += {
		dcc_file_name:    string &log &optional;
		dcc_file_size:    count  &log &optional;
		dcc_mime_type:    string &log &optional;
		
		## The file handle for the file to be extracted
		extraction_file:  file &log &optional;
		
		## A boolean to indicate if the current file transfer should be extraced.
		extract_file:     bool &default=F;
		
		## The count of the number of file that have been extracted during the session.
		num_extracted_files:   count &default=0;
	};
}

global dcc_expected_transfers: table[addr, port] of Info = table();

event file_transferred(c: connection, prefix: string, descr: string,
                       mime_type: string) &priority=3
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] !in dcc_expected_transfers )
		return;
		
	local irc = dcc_expected_transfers[id$resp_h, id$resp_p];
	
	irc$dcc_mime_type = mime_type;

	if ( extract_file_types in mime_type )
		{
		irc$extract_file = T;
		add irc$tags[EXTRACTED_FILE];
		
		local suffix = fmt("%d.dat", ++irc$num_extracted_files);
		local fname = generate_extraction_filename(extraction_prefix, c, suffix);
		irc$extraction_file = open(fname);
		}
	
	}
	
event file_transferred(c: connection, prefix: string, descr: string,
			mime_type: string) &priority=-4
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] !in dcc_expected_transfers )
		return;

	local irc = dcc_expected_transfers[id$resp_h, id$resp_p];

	if ( irc$extract_file && irc?$extraction_file )
		set_contents_file(id, CONTENTS_RESP, irc$extraction_file);
	
	# Delete these values in case another DCC transfer 
	# happens during the IRC session.
	delete irc$extract_file;
	delete irc$extraction_file;
	delete irc$dcc_file_name;
	delete irc$dcc_file_size;
	delete irc$dcc_mime_type;
	delete dcc_expected_transfers[id$resp_h, id$resp_p];
	}


event irc_server(c: connection, prefix: string, data: string) &priority=5
	{
	local parts = split_all(data, / /);
	local command = parts[1];
	if ( command == "PRIVMSG" &&
	     /[dD][cC][cC] [sS][eE][nN][dD]/ in data &&
	     |parts| > 12 &&
	     /^[0-9]*$/ == parts[|parts|-4] &&
	     /^[0-9]*$/ == parts[|parts|-2] )
		{
		c$irc$command = "DCC SEND";
		local ex_h = count_to_v4_addr(extract_count(parts[|parts|-4]));
		local ex_p = to_port(to_count(parts[|parts|-2]), tcp);
		c$irc$dcc_file_name = parts[|parts|-6];
		c$irc$dcc_file_size = extract_count(parts[|parts|]);
		expect_connection(c$id$orig_h, ex_h, ex_p, ANALYZER_FILE, 5 min);
		dcc_expected_transfers[ex_h, ex_p] = c$irc;
		}
	}

event expected_connection_seen(c: connection, a: count) &priority=10
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] in dcc_expected_transfers )
		add c$service["irc-dcc-data"];
	}
