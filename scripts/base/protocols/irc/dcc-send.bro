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
		extraction_file:       string &log &optional;

		## A boolean to indicate if the current file transfer should be extracted.
		extract_file:          bool &default=F;
	};
}

global dcc_expected_transfers: table[addr, port] of Info &read_expire=5mins;

function set_dcc_mime(f: fa_file)
	{
	if ( ! f?$conns ) return;

	for ( cid in f$conns )
		{
		local c: connection = f$conns[cid];

		if ( [cid$resp_h, cid$resp_p] !in dcc_expected_transfers ) next;

		local s = dcc_expected_transfers[cid$resp_h, cid$resp_p];

		s$dcc_mime_type = f$mime_type;
		}
	}

function set_dcc_extraction_file(f: fa_file, filename: string)
	{
	if ( ! f?$conns ) return;

	for ( cid in f$conns )
		{
		local c: connection = f$conns[cid];

		if ( [cid$resp_h, cid$resp_p] !in dcc_expected_transfers ) next;

		local s = dcc_expected_transfers[cid$resp_h, cid$resp_p];

		s$extraction_file = filename;
		}
	}

function get_extraction_name(f: fa_file): string
	{
	local r = fmt("%s-%s.dat", extraction_prefix, f$id);
	return r;
	}

# this handler sets the IRC::Info mime type
event file_new(f: fa_file) &priority=5
	{
	if ( ! f?$source ) return;
	if ( f$source != "IRC_DATA" ) return;
	if ( ! f?$mime_type ) return;

	set_dcc_mime(f);
	}

# this handler check if file extraction is desired
event file_new(f: fa_file) &priority=5
	{
	if ( ! f?$source ) return;
	if ( f$source != "IRC_DATA" ) return;

	local fname: string;

	if ( f?$mime_type && extract_file_types in f$mime_type )
		{
		fname = get_extraction_name(f);
		FileAnalysis::add_analyzer(f, [$tag=FileAnalysis::ANALYZER_EXTRACT,
		                               $extract_filename=fname]);
		set_dcc_extraction_file(f, fname);
		return;
		}

	if ( ! f?$conns ) return;

	for ( cid in f$conns )
		{
		local c: connection = f$conns[cid];

		if ( [cid$resp_h, cid$resp_p] !in dcc_expected_transfers ) next;

		local s = dcc_expected_transfers[cid$resp_h, cid$resp_p];

		if ( ! s$extract_file ) next;

		fname = get_extraction_name(f);
		FileAnalysis::add_analyzer(f, [$tag=FileAnalysis::ANALYZER_EXTRACT,
		                               $extract_filename=fname]);
		s$extraction_file = fname;
		return;
		}
	}

function log_dcc(f: fa_file)
	{
	if ( ! f?$conns ) return;

	for ( cid in f$conns )
		{
		local c: connection = f$conns[cid];

		if ( [cid$resp_h, cid$resp_p] !in dcc_expected_transfers ) next;

		local irc = dcc_expected_transfers[cid$resp_h, cid$resp_p];

		local tmp = irc$command;
		irc$command = "DCC";
		Log::write(IRC::LOG, irc);
		irc$command = tmp;

		# Delete these values in case another DCC transfer 
		# happens during the IRC session.
		delete irc$extract_file;
		delete irc$extraction_file;
		delete irc$dcc_file_name;
		delete irc$dcc_file_size;
		delete irc$dcc_mime_type;

		return;
		}
	}

event file_new(f: fa_file) &priority=-5
	{
	if ( ! f?$source ) return;
	if ( f$source != "IRC_DATA" ) return;

	log_dcc(f);
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
	expect_connection(to_addr("0.0.0.0"), address, p, ANALYZER_IRC_DATA, 5 min);
	dcc_expected_transfers[address, p] = c$irc;
	}

event expected_connection_seen(c: connection, a: count) &priority=10
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] in dcc_expected_transfers )
		add c$service["irc-dcc-data"];
	}

event connection_state_remove(c: connection) &priority=-5
	{
	delete dcc_expected_transfers[c$id$resp_h, c$id$resp_p];
	}
