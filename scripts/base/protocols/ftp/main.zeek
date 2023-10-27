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
@load base/frameworks/cluster
@load base/frameworks/notice/weird
@load base/protocols/conn/removal-hooks

module FTP;

export {
	## The FTP protocol logging stream identifier.
	redef enum Log::ID += { LOG };

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## List of commands that should have their command/response pairs logged.
	option logged_commands = {
		"APPE", "DELE", "RETR", "STOR", "STOU", "ACCT", "PORT", "PASV", "EPRT",
		"EPSV"
	};

	## User IDs that can be considered "anonymous".
	option guest_ids = { "anonymous", "ftp", "ftpuser", "guest" };

	## This record is to hold a parsed FTP reply code.  For example, for the
	## 201 status code, the digits would be parsed as: x->2, y->0, z->1.
	type ReplyCode: record {
		x: count;
		y: count;
		z: count;
	};

	## Parse FTP reply codes into the three constituent single digit values.
	global parse_ftp_reply_code: function(code: count): ReplyCode;

	## Event that can be handled to access the :zeek:type:`FTP::Info`
	## record as it is sent on to the logging framework.
	global log_ftp: event(rec: Info);

	## FTP finalization hook.  Remaining FTP info may get logged when it's called.
	global finalize_ftp: Conn::RemovalHook;

	## FTP data finalization hook.  Expected FTP data channel state may
	## get purged when called.
	global finalize_ftp_data: hook(c: connection);

	## Allow a client to send this many commands before the server
	## sends a reply. If this value is exceeded a weird named
	## FTP_too_many_pending_commands is logged for the connection.
	option max_pending_commands = 20;

	## Truncate the user field in the log to that many bytes to avoid
	## excessive logging volume as this values is replicated in each
	## of the entries related to an FTP session.
	option max_user_length = 128;

	## Truncate the password field in the log to that many bytes to avoid
	## excessive logging volume as this values is replicated in each
	## of the entries related to an FTP session.
	option max_password_length = 128;

	## Truncate the arg field in the log to that many bytes to avoid
	## excessive logging volume.
	option max_arg_length = 4096;

	## Truncate the reply_msg field in the log to that many bytes to avoid
	## excessive logging volume.
	option max_reply_msg_length = 4096;
}

# Add the state tracking information variable to the connection record
redef record connection += {
	ftp: Info &optional;
	ftp_data_reuse: bool &default=F;
};

const ports = { 21/tcp, 2811/tcp };
redef likely_server_ports += { ports };

event zeek_init() &priority=5
	{
	Log::create_stream(FTP::LOG, [$columns=Info, $ev=log_ftp, $path="ftp", $policy=log_policy]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_FTP, ports);
	}

# Establish the variable for tracking expected connections.
global ftp_data_expected: table[addr, port] of Info &read_expire=5mins;

function minimize_info(info: Info): Info &is_used
	{
	# Just minimal data for sending to other remote Zeek processes.
	# Generally, only data that's consistent across an entire FTP session or
	# relevant to an expected data transfer would even be usable.
	local rval: Info;
	rval$ts = info$ts;
	rval$uid= info$uid;
	rval$id= info$id;
	rval$user = info$user;
	rval$passive = info$passive;
	rval$pending_commands = PendingCmds();
	return rval;
	}

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

function ftp_relay_topic(): string &is_used
	{
	local rval = Cluster::rr_topic(Cluster::proxy_pool, "ftp_transfer_rr_key");

	if ( rval == "" )
		# No proxy is alive, so relay via manager instead.
		return Cluster::manager_topic;

	return rval;
	}

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
		Conn::register_removal_hook(c, finalize_ftp);

		# Add a shim command so the server can respond with some init response.
		add_pending_cmd(c$ftp$pending_commands, ++c$ftp$command_seq, "<init>", "");
		}
	}

function ftp_message(c: connection)
	{
	if ( ! c?$ftp ) return;
	local s: Info = c$ftp;
	s$ts=s$cmdarg$ts;
	s$command=s$cmdarg$cmd;

	s$arg = s$cmdarg$arg;
	if ( s$cmdarg$cmd in file_cmds )
		s$arg = build_url_ftp(s);

	# Avoid logging arg or reply_msg that are too big.
	if ( |s$arg| > max_arg_length )
		{
		Reporter::conn_weird("FTP_arg_too_long", c, cat(|s$arg|), "FTP");
		s$arg = s$arg[:max_arg_length];
		}

	if ( s?$reply_msg && |s$reply_msg| > max_reply_msg_length )
		{
		Reporter::conn_weird("FTP_reply_msg_too_long", c, cat(|s$reply_msg|), "FTP");
		s$reply_msg = s$reply_msg[:max_reply_msg_length];
		}


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

event sync_add_expected_data(s: Info, chan: ExpectedDataChannel) &is_used
	{
@if ( Cluster::local_node_type() == Cluster::PROXY ||
      Cluster::local_node_type() == Cluster::MANAGER )
	Broker::publish(Cluster::worker_topic, sync_add_expected_data, minimize_info(s), chan);
@else
	ftp_data_expected[chan$resp_h, chan$resp_p] = s;
	Analyzer::schedule_analyzer(chan$orig_h, chan$resp_h, chan$resp_p,
	                            Analyzer::ANALYZER_FTP_DATA,
	                            5mins);
@endif
	}

event sync_remove_expected_data(resp_h: addr, resp_p: port) &is_used
	{
@if ( Cluster::local_node_type() == Cluster::PROXY ||
      Cluster::local_node_type() == Cluster::MANAGER )
	Broker::publish(Cluster::worker_topic, sync_remove_expected_data, resp_h, resp_p);
@else
	delete ftp_data_expected[resp_h, resp_p];
@endif
	}

function add_expected_data_channel(s: Info, chan: ExpectedDataChannel)
	{
	s$passive = chan$passive;
	s$data_channel = chan;
	ftp_data_expected[chan$resp_h, chan$resp_p] = s;
	Analyzer::schedule_analyzer(chan$orig_h, chan$resp_h, chan$resp_p,
	                            Analyzer::ANALYZER_FTP_DATA,
	                            5mins);
@if ( Cluster::is_enabled() )
	Broker::publish(ftp_relay_topic(), sync_add_expected_data, minimize_info(s), chan);
@endif
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
		if ( remove_pending_cmd(c$ftp$pending_commands, c$ftp$cmdarg) )
			ftp_message(c);
		}

	local id = c$id;
	set_ftp_session(c);

	# Queue up the new command and argument
	if ( |c$ftp$pending_commands| < max_pending_commands )
		add_pending_cmd(c$ftp$pending_commands, ++c$ftp$command_seq, command, arg);
	else
		Reporter::conn_weird("FTP_too_many_pending_commands", c,
				     cat(|c$ftp$pending_commands|), "FTP");

	if ( command == "USER" )
		{
		if ( |arg| > max_user_length )
			{
			Reporter::conn_weird("FTP_user_too_long", c, cat(|arg|), "FTP");
			arg = arg[:max_user_length];
			}

		c$ftp$user = arg;
		}
	else if ( command == "PASS" )
		{
		if ( |arg| > max_password_length )
			{
			Reporter::conn_weird("FTP_password_too_long", c, cat(|arg|), "FTP");
			arg = arg[:max_password_length];
			}

		c$ftp$password = arg;
		}
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

	# Skip matching up intermediate reply lines (that do not have a
	# valid status code) with pending commands. Because they may not
	# have a proper status code, there's little point setting whatever
	# their reply_code and reply_msg are on the command.
	#
	# There's a quirk: Some FTP servers return(ed?) replies like the
	# following, violating the multi-line reply protocol:
	#
	#  c: STOR intermol.ps
	#  s: 150 Opening ASCII mode data connection for 'intermol.ps'.
	#  s: 230- WARNING! 4 bare linefeeds received in ASCII mode
	#  s:    File may not have transferred correctly.
	#  s: 226 Transfer complete.
	#
	# This is a multiline response started with 230-, but never finalized
	# with the same status code. It should have been completed with
	# "230 <some final message>", but instead was completed with "226 ...".
	# This confuses our parser, returning cont_resp = T for all following
	# server messages. This caused a regression as the current command wasn't
	# updated for logging.
	#
	# The regex below is a best effort to keep existing behavior
	# in face of such traffic. It matches on messages that look
	# like valid status codes (starting with 3 digits followed by
	# at least 10 ASCII characters).
	#
	# There's the following in RFC 959, so in the future we could push
	# the detection/logic down into the parser instead of here.
	#
	#   If an intermediary line begins with a 3-digit number, the Server
	#   must pad the front to avoid confusion.
	#
	if ( cont_resp && code == 0 && c$ftp?$reply_code )
		{
		if ( /^[1-9][0-9]{2} [[:print:]]{10}.*/ !in msg )
			return;
		else
			{
			# This might be worth a weird, but not sure it's
			# worth it and how trigger happy it could be.
			# Reporter::conn_weird("FTP_intermediate_line_with_reply_code", c, msg, "FTP");
			}
		}

	c$ftp$cmdarg = get_pending_cmd(c$ftp$pending_commands, code, msg);
	c$ftp$reply_code = code;
	c$ftp$reply_msg = msg;

	# Do not parse out information from any but the first reply line.
	if ( cont_resp )
		return;

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
		c$ftp$file_size = extract_count(msg, F);
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

	if ( [c$ftp$cmdarg$cmd, code] in directory_cmds && ! c$ftp$cmdarg$cwd_consumed )
		{
		c$ftp$cmdarg$cwd_consumed = T;

		if ( c$ftp$cmdarg$cmd == "CWD" )
			c$ftp$cwd = build_path_compressed(c$ftp$cwd, c$ftp$cmdarg$arg);

		else if ( c$ftp$cmdarg$cmd == "CDUP" )
			c$ftp$cwd = build_path_compressed(c$ftp$cwd, "/..");

		else if ( c$ftp$cmdarg$cmd == "PWD" || c$ftp$cmdarg$cmd == "XPWD" )
			c$ftp$cwd = extract_path(msg);
		}

	# In case there are multiple commands queued, go ahead and remove the
	# command here and log because we can't do the normal processing pipeline
	# to wait for a new command before logging the command/response pair.
	if ( |c$ftp$pending_commands| > 1 )
		{
		remove_pending_cmd(c$ftp$pending_commands, c$ftp$cmdarg);
		ftp_message(c);
		}
	}

event scheduled_analyzer_applied(c: connection, a: Analyzer::Tag) &priority=10
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] in ftp_data_expected )
		{
		add c$service["ftp-data"];
		Conn::register_removal_hook(c, finalize_ftp_data);
		}
	}

event file_transferred(c: connection, prefix: string, descr: string,
			mime_type: string) &priority=5
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] in ftp_data_expected )
		{
		local s = ftp_data_expected[id$resp_h, id$resp_p];
		s$mime_type = split_string1(mime_type, /;/)[0];
		}
	}

event connection_reused(c: connection) &priority=5
	{
	if ( "ftp-data" in c$service )
		c$ftp_data_reuse = T;
	}

hook finalize_ftp_data(c: connection)
	{
	if ( c$ftp_data_reuse ) return;
	if ( [c$id$resp_h, c$id$resp_p] in ftp_data_expected )
		{
		delete ftp_data_expected[c$id$resp_h, c$id$resp_p];
@if ( Cluster::is_enabled() )
		Broker::publish(ftp_relay_topic(), sync_remove_expected_data, c$id$resp_h, c$id$resp_p);
@endif
		}
	}

# Covers connections terminated by RST.
hook finalize_ftp(c: connection)
	{
	if ( ! c?$ftp ) return;

	for ( _, cmdarg in c$ftp$pending_commands )
		{
		c$ftp$cmdarg = cmdarg;
		ftp_message(c);
		}
	}
