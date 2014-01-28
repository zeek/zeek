##! The logging this script does is primarily focused on logging FTP commands
##! along with metadata.  For example, if files are transferred, the argument
##! will take on the full path that the client is at along with the requested
##! file name.

@load ./info
@load ./utils
@load ./utils-commands
@load base/utils/paths
@load base/utils/numbers
@load base/utils/addrs

module FTP;

export {
	## The FTP protocol logging stream identifier.
	redef enum Log::ID += { LOG };

	## List of commands that should have their command/response pairs logged.
	const logged_commands = {
		"APPE", "DELE", "RETR", "STOR", "STOU", "ACCT", "PORT", "PASV", "EPRT",
		"EPSV"
	} &redef;

	## User IDs that can be considered "anonymous".
	const guest_ids = { "anonymous", "ftp", "ftpuser", "guest" } &redef;

	## This record is to hold a parsed FTP reply code.  For example, for the
	## 201 status code, the digits would be parsed as: x->2, y->0, z->1.
	type ReplyCode: record {
		x: count;
		y: count;
		z: count;
	};

	## Parse FTP reply codes into the three constituent single digit values.
	global parse_ftp_reply_code: function(code: count): ReplyCode;

	## Event that can be handled to access the :bro:type:`FTP::Info`
	## record as it is sent on to the logging framework.
	global log_ftp: event(rec: Info);
}

# Add the state tracking information variable to the connection record
redef record connection += {
	ftp: Info &optional;
	ftp_data_reuse: bool &default=F;
};

const ports = { 21/tcp, 2811/tcp };
redef likely_server_ports += { ports };

event bro_init() &priority=5
	{
	Log::create_stream(FTP::LOG, [$columns=Info, $ev=log_ftp]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_FTP, ports);
	}

# Establish the variable for tracking expected connections.
global ftp_data_expected: table[addr, port] of Info &read_expire=5mins;

## A set of commands where the argument can be expected to refer
## to a file or directory.
const file_cmds = {
	"APPE", "CWD", "DELE", "MKD", "RETR", "RMD", "RNFR", "RNTO",
	"STOR", "STOU", "REST", "SIZE", "MDTM",
};

## Commands that either display or change the current working directory along
## with the response codes to indicate a successful command.
const directory_cmds = {
	["CWD",  250],
	["CDUP", 200], # typo in RFC?
	["CDUP", 250], # as found in traces
	["PWD",  257],
	["XPWD", 257],
};

function parse_ftp_reply_code(code: count): ReplyCode
	{
	local a: ReplyCode;

	a$z = code % 10;

	code = code / 10;
	a$y = code % 10;

	code = code / 10;
	a$x = code % 10;

	return a;
	}

function set_ftp_session(c: connection)
	{
	if ( ! c?$ftp )
		{
		local s: Info;
		s$ts=network_time();
		s$uid=c$uid;
		s$id=c$id;
		c$ftp=s;

		# Add a shim command so the server can respond with some init response.
		add_pending_cmd(c$ftp$pending_commands, "<init>", "");
		}
	}

function ftp_message(s: Info)
	{
	s$ts=s$cmdarg$ts;
	s$command=s$cmdarg$cmd;

	s$arg = s$cmdarg$arg;
	if ( s$cmdarg$cmd in file_cmds )
		s$arg = build_url_ftp(s);

	if ( s$arg == "" )
		delete s$arg;

	if ( s?$password &&
	     ! s$capture_password &&
	     to_lower(s$user) !in guest_ids )
		{
		s$password = "<hidden>";
		}

	if ( s?$cmdarg && s$command in logged_commands)
		Log::write(FTP::LOG, s);

	# The MIME and file_size fields are specific to file transfer commands
	# and may not be used in all commands so they need reset to "blank"
	# values after logging.
	delete s$mime_type;
	delete s$file_size;
	# Same with data channel.
	delete s$data_channel;
	}

function add_expected_data_channel(s: Info, chan: ExpectedDataChannel)
	{
	s$passive = chan$passive;
	s$data_channel = chan;
	ftp_data_expected[chan$resp_h, chan$resp_p] = s;
	Analyzer::schedule_analyzer(chan$orig_h, chan$resp_h, chan$resp_p,
	                            Analyzer::ANALYZER_FTP_DATA,
	                            5mins);
	}

event ftp_request(c: connection, command: string, arg: string) &priority=5
	{
	# Write out the previous command when a new command is seen.
	# The downside here is that commands definitely aren't logged until the
	# next command is issued or the control session ends.  In practicality
	# this isn't an issue, but I suppose it could be a delay tactic for
	# attackers.
	if ( c?$ftp && c$ftp?$cmdarg && c$ftp?$reply_code )
		{
		remove_pending_cmd(c$ftp$pending_commands, c$ftp$cmdarg);
		ftp_message(c$ftp);
		}

	local id = c$id;
	set_ftp_session(c);

	# Queue up the new command and argument
	add_pending_cmd(c$ftp$pending_commands, command, arg);

	if ( command == "USER" )
		c$ftp$user = arg;

	else if ( command == "PASS" )
		c$ftp$password = arg;

	else if ( command == "PORT" || command == "EPRT" )
		{
		local data = (command == "PORT") ?
				parse_ftp_port(arg) : parse_eftp_port(arg);

		if ( data$valid )
			{
			add_expected_data_channel(c$ftp, [$passive=F, $orig_h=id$resp_h,
			                                  $resp_h=data$h, $resp_p=data$p]);
			}
		else
			{
			# TODO: raise a notice?  does anyone care?
			}
		}
	}


event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool) &priority=5
	{
	set_ftp_session(c);
	c$ftp$cmdarg = get_pending_cmd(c$ftp$pending_commands, code, msg);
	c$ftp$reply_code = code;
	c$ftp$reply_msg = msg;

	# TODO: figure out what to do with continued FTP response (not used much)
	if ( cont_resp ) return;

	# TODO: do some sort of generic clear text login processing here.
	local response_xyz = parse_ftp_reply_code(code);
	#if ( response_xyz$x == 2 &&  # successful
	#     session$cmdarg$cmd == "PASS" )
	#	do_ftp_login(c, session);

	if ( (code == 150 && c$ftp$cmdarg$cmd == "RETR") ||
	     (code == 213 && c$ftp$cmdarg$cmd == "SIZE") )
		{
		# NOTE: This isn't exactly the right thing to do for SIZE since the size
		#       on a different file could be checked, but the file size will
		#       be overwritten by the server response to the RETR command
		#       if that's given as well which would be more correct.
		c$ftp$file_size = extract_count(msg);
		}

	# PASV and EPSV processing
	else if ( (code == 227 || code == 229) &&
	          (c$ftp$cmdarg$cmd == "PASV" || c$ftp$cmdarg$cmd == "EPSV") )
		{
		local data = (code == 227) ? parse_ftp_pasv(msg) : parse_ftp_epsv(msg);

		if ( data$valid )
			{
			c$ftp$passive=T;

			if ( code == 229 && data$h == [::] )
				data$h = c$id$resp_h;

			add_expected_data_channel(c$ftp, [$passive=T, $orig_h=c$id$orig_h,
			                          $resp_h=data$h, $resp_p=data$p]);
			}
		else
			{
			# TODO: do something if there was a problem parsing the PASV message?
			}
		}

	if ( [c$ftp$cmdarg$cmd, code] in directory_cmds )
		{
		if ( c$ftp$cmdarg$cmd == "CWD" )
			c$ftp$cwd = build_path(c$ftp$cwd, c$ftp$cmdarg$arg);

		else if ( c$ftp$cmdarg$cmd == "CDUP" )
			c$ftp$cwd = cat(c$ftp$cwd, "/..");

		else if ( c$ftp$cmdarg$cmd == "PWD" || c$ftp$cmdarg$cmd == "XPWD" )
			c$ftp$cwd = extract_path(msg);
		}

	# In case there are multiple commands queued, go ahead and remove the
	# command here and log because we can't do the normal processing pipeline
	# to wait for a new command before logging the command/response pair.
	if ( |c$ftp$pending_commands| > 1 )
		{
		remove_pending_cmd(c$ftp$pending_commands, c$ftp$cmdarg);
		ftp_message(c$ftp);
		}
	}

event scheduled_analyzer_applied(c: connection, a: Analyzer::Tag) &priority=10
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] in ftp_data_expected )
		add c$service["ftp-data"];
	}

event file_transferred(c: connection, prefix: string, descr: string,
			mime_type: string) &priority=5
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] in ftp_data_expected )
		{
		local s = ftp_data_expected[id$resp_h, id$resp_p];
		s$mime_type = split1(mime_type, /;/)[1];
		}
	}

event connection_reused(c: connection) &priority=5
	{
	if ( "ftp-data" in c$service )
		c$ftp_data_reuse = T;
	}

event connection_state_remove(c: connection) &priority=-5
	{
	if ( c$ftp_data_reuse ) return;
	delete ftp_data_expected[c$id$resp_h, c$id$resp_p];
	}

# Use state remove event to cover connections terminated by RST.
event connection_state_remove(c: connection) &priority=-5
	{
	if ( ! c?$ftp ) return;

	for ( ca in c$ftp$pending_commands )
		{
		c$ftp$cmdarg = c$ftp$pending_commands[ca];
		ftp_message(c$ftp);
		}
	}
