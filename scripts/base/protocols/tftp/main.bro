
module TFTP;

export {
	## The TFTP protocol logging stream identifier.
	redef enum Log::ID += { LOG };

	type Info: record {
		## Time when the transfer started.
		ts:		time		&log;
		## Unique ID for the connection.
		uid:		string		&log;
		## The connection's 4-tuple of endpoint address/ports.
		id:		conn_id		&log;
		## Command given by the client.
		command:	string		&log;
		## Argument for the command if one was given.
		arg:		string		&log;
		## File transfer mode (octet, netascii, etc.).
		xfer_mode:	string		&log;

		## Libmagic "sniffed" file type if the command indicates a file transfer.
		mime_type:	string		&log &optional;
		## Libmagic "sniffed" file description if the command indicates a file transfer.
		mime_desc:	string		&log &optional;
		## Size of the file if the command indicates a file transfer.
		file_size:	count		&log &optional;
		
		## Reply code from the server in response to the command.
		reply_code:	count		&log &optional;
		## Reply message from the server in response to the command.
		reply_msg:	string		&log &optional;
	};

	## Event that can be handled to access the :bro:type:`TFTP::Info`
	## record as it is sent on to the logging framework.
	global log_tftp: event(rec: Info);
}

# Add the state tracking information variable to the connection record
redef record connection += {
	tftp: Info &optional;
};

# Establish the variable for tracking expected connections.
#global tftp_data_expected: table[addr, port] of Info &create_expire=5mins;

const ports = { 69/udp } &redef;
redef likely_server_ports += { ports };


event bro_init() &priority=5
	{
	Log::create_stream(TFTP::LOG, [$columns=Info]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_TFTP, ports);
	}

event tftp_read_request(c: connection, filename: string, trans_type: string)
	{
	local info: Info;
	info$ts = network_time();
	info$uid = c$uid;
	info$id = c$id;

	info$command = "read";
	info$arg = filename;
	info$xfer_mode = trans_type;

	c$tftp = info;

	#tftp_data_expected[c$id$orig_h, c$id$orig_p] = c$tftp;
	#Analyzer::schedule_analyzer(c$id$resp_h, c$id$orig_h, c$id$orig_p, Analyzer::ANALYZER_TFTP, 5mins);
	Log::write(TFTP::LOG, c$tftp);
	}

event tftp_write_request(c: connection, filename: string, trans_type: string)
	{
	local info: Info;
	info$ts = network_time();
	info$uid = c$uid;
	info$id = c$id;

	info$command = "write";
	info$arg = filename;
	info$xfer_mode = trans_type;

	c$tftp = info;

	#tftp_data_expected[c$id$orig_h, c$id$orig_p] = c$tftp;
	#Analyzer::schedule_analyzer(c$id$resp_h, c$id$orig_h, c$id$orig_p, Analyzer::ANALYZER_TFTP, 5mins);
	Log::write(TFTP::LOG, c$tftp);
	}

event scheduled_analyzer_applied(c: connection, a: Analyzer::Tag) &priority=10
	{
	local id = c$id;
	#if ( [id$resp_h, id$resp_p] in tftp_data_expected )
	#	add c$service["tftp-data"];
	}
