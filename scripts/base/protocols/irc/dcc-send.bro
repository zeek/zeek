##! File extraction and introspection for DCC transfers over IRC.
##!
##! There is a major problem with this script in the cluster context because
##! we might see A send B a message that a DCC connection is to be expected,
##! but that connection will actually be between B and C which could be 
##! analyzed on a different worker.
##!

# Example line from IRC server indicating that the DCC SEND is about to start:
#    PRIVMSG my_nick :^ADCC SEND whateverfile.zip 3640061780 1026 41709^A

@load ./main
@load base/utils/files

module IRC;

export {
	## Pattern of file mime types to extract from IRC DCC file transfers.
	const extract_file_types = /NO_DEFAULT/ &redef;

	## On-disk prefix for files to be extracted from IRC DCC file transfers.
	const extraction_prefix = "irc-dcc-item" &redef;

	redef record Info += {
		## DCC filename requested.
		dcc_file_name:         string &log &optional;
		## Size of the DCC transfer as indicated by the sender.
		dcc_file_size:         count  &log &optional;
		## Sniffed mime type of the file.
		dcc_mime_type:         string &log &optional;
		
		## The file handle for the file to be extracted
		extraction_file:       file &log &optional;
		
		## A boolean to indicate if the current file transfer should be extracted.
		extract_file:          bool &default=F;
		
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
	
	irc$dcc_mime_type = split1(mime_type, /;/)[1];

	if ( extract_file_types == irc$dcc_mime_type )
		{
		irc$extract_file = T;
		}
		
	if ( irc$extract_file )
		{
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

	local tmp = irc$command;
	irc$command = "DCC";
	Log::write(IRC::LOG, irc);
	irc$command = tmp;

	if ( irc?$extraction_file )
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

event irc_dcc_message(c: connection, is_orig: bool,
			prefix: string, target: string,
			dcc_type: string, argument: string,
			address: addr, dest_port: count, size: count) &priority=5
	{
	set_session(c);
	if ( dcc_type != "SEND" )
            return;
	c$irc$dcc_file_name = argument;
	c$irc$dcc_file_size = size;
	local p = count_to_port(dest_port, tcp);
	expect_connection(to_addr("0.0.0.0"), address, p, ANALYZER_FILE, 5 min);
	dcc_expected_transfers[address, p] = c$irc;
	}

event expected_connection_seen(c: connection, a: count) &priority=10
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] in dcc_expected_transfers )
		add c$service["irc-dcc-data"];
	}
