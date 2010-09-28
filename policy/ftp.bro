# $Id: ftp.bro 6726 2009-06-07 22:09:55Z vern $

@load notice
@load conn
@load scan
@load hot-ids
@load terminate-connection

@load ftp-cmd-arg

module FTP;

export {
	# Indexed by source & destination addresses and the id.
	const skip_hot: set[addr, addr, string] &redef;

   # see: http://packetstormsecurity.org/UNIX/penetration/rootkits/index4.html
   # for current list of rootkits to include here

	const hot_files =
		  /.*(etc\/|master\.)?(passwd|shadow|s?pwd\.db)/
		| /.*snoop\.(tar|tgz).*/
		| /.*bnc\.(tar|tgz).*/
		| /.*datapipe.*/
		| /.*ADMw0rm.*/
		| /.*newnick.*/
		| /.*sniffit.*/
		| /.*neet\.(tar|tgz).*/
		| /.*\.\.\..*/
		| /.*ftpscan.txt.*/
		| /.*jcc.pdf.*/
		| /.*\.[Ff]rom.*/
		| /.*sshd\.(tar|tgz).*/
		| /.*\/rk7.*/
		| /.*rk7\..*/
		| /.*[aA][dD][oO][rR][eE][bB][sS][dD].*/
		| /.*[tT][aA][gG][gG][eE][dD].*/
		| /.*shv4\.(tar|tgz).*/
		| /.*lrk\.(tar|tgz).*/
		| /.*lyceum\.(tar|tgz).*/
		| /.*maxty\.(tar|tgz).*/
		| /.*rootII\.(tar|tgz).*/
		| /.*invader\.(tar|tgz).*/
	&redef;

	const hot_guest_files =
		  /.*\.rhosts/
		| /.*\.forward/
		&redef;

	const hot_cmds: table[string] of pattern = {
		["SITE"] = /[Ee][Xx][Ee][Cc].*/,
	} &redef;

	const excessive_filename_len = 250 &redef;
	const excessive_filename_trunc_len = 32 &redef;

	const guest_ids = { "anonymous", "ftp", "guest", } &redef;

	# Invalid PORT/PASV directives that exactly match the following
	# don't generate notice's.
	const ignore_invalid_PORT =
		/,0,0/	# these are common, dunno why
	&redef;

	# Some servers generate particular privileged PASV ports for benign
	# reasons (presumably to tunnel through firewalls, sigh).
	const ignore_privileged_PASVs = { ssh, } &redef;

	# Pairs of IP addresses for which we shouldn't bother logging if one
	# of them is used in lieu of the other in a PORT or PASV directive.

	const skip_unexpected: set[addr] = {
		15.253.0.10, 15.253.48.10, 15.254.56.2,		# hp.com
		gvaona1.cns.hp.com,
	} &redef;

	const skip_unexpected_net: set[addr] &redef;

	const log_file = open_log_file("ftp") &redef;

	redef enum Notice += {
		FTP_UnexpectedConn,	# FTP data transfer from unexpected src
		FTP_ExcessiveFilename,	# very long filename seen
		FTP_PrivPort,		# privileged port used in PORT/PASV;
					#   $sub says which
		FTP_BadPort,		# bad format in PORT/PASV;
					#   $sub says which
		FTP_Sensitive,		# sensitive connection -
					#   not more specific
		FTP_SiteExecAttack,	# specific "site exec" attack seen
	};

	type ftp_session_info: record {
		id: count;
		connection_id: conn_id;
		user: string;
		anonymized_user: string;
		anonymous_login: bool;

		request: string;	# pending request or requests
		num_requests: count;	# count of pending requests
		request_t: time;	# time of request
		log_if_not_denied: bool;	# log unless code 530 on reply
		log_if_not_unavail: bool;	# log unless code 550 on reply
		log_it: bool;		# if true, log the request(s)

		reply_code: count;	# the most recent reply code
		cwd: string;		# current working directory

		pending_requests: ftp_pending_cmds;	# pending requests
		delayed_request_rewrite: table[count] of ftp_cmd_arg;

		expected: set[addr, port]; # data connections we expect
	};

	type ftp_expected_conn: record {
		host: addr;
		session: ftp_session_info;
	};

	global ftp_sessions: table[conn_id] of ftp_session_info &persistent;
}


redef capture_filters += { ["ftp"] = "port ftp" };

# DPM configuration.
global ftp_ports = { 21/tcp } &redef; 
redef dpd_config += { [ANALYZER_FTP] = [$ports = ftp_ports] };

function is_ftp_conn(c: connection): bool
	{
	return c$id$resp_p == ftp;
	}

type ftp_reply_code: record {
	x: count;	# high-order (3rd digit)
	y: count;	# middle (2nd) digit
	z: count;	# bottom digit
};

global ftp_session_id = 0;

# Indexed by the responder pair, yielding the address expected to connect to it.
global ftp_data_expected: table[addr, port] of ftp_expected_conn &persistent &create_expire = 1 min;

const ftp_init_dir: table[addr, string] of string = {
	[131.243.1.10, "anonymous"] = "/",
} &default = "<unknown>/";

const ftp_file_cmds = {
	"APPE", "CWD", "DELE", "MKD", "RETR", "RMD", "RNFR", "RNTO",
	"STOR", "STOU",
};

const ftp_absolute_path_pat = /(\/|[A-Za-z]:[\\\/]).*/;

const ftp_dir_operation = {
	["CWD", 250],
	["CDUP", 200],	# typo in RFC?
	["CDUP", 250],	# as found in traces
	["PWD", 257],
	["XPWD", 257],
};

const ftp_skip_replies = {
	150,	# "status okay - about to open connection"
	331	# "user name okay, need password"
};

const ftp_replies: table[count] of string = {
	[150] = "ok",
	[200] = "ok",
	[220] = "ready for new user",
	[221] = "closed",
	[226] = "complete",
	[230] = "logged in",
	[250] = "ok",
	[257] = "done",
	[331] = "id ok",
	[500] = "syntax error",
	[530] = "denied",
	[550] = "unavail",
};

const ftp_other_replies = { ftp_replies };

const ftp_all_cmds: set[string] = {
	"<init>", "<missing>",
	"USER", "PASS", "ACCT",
	"CWD", "CDUP", "SMNT",
	"REIN", "QUIT",
	"PORT", "PASV", "MODE", "TYPE", "STRU",
	"ALLO", "REST", "STOR", "STOU", "RETR", "LIST", "NLST", "APPE",
	"RNFR", "RNTO", "DELE", "RMD", "MKD", "PWD", "ABOR",
	"SYST", "STAT", "HELP",
	"SITE", "NOOP",

	# FTP extensions
	"SIZE", "MDTM", "MLST", "MLSD",
	"EPRT", "EPSV",
};

const ftp_tested_cmds: set[string] = {};
const ftp_untested_cmds: set[string] = { ftp_all_cmds };

global ftp_first_seen_cmds: set[string];
global ftp_unlisted_cmds: set[string];

# const ftp_state_diagram: table[string] of count = {
#	["ABOR", "ALLO", "DELE", "CWD", "CDUP",
#	 "SMNT", "HELP", "MODE", "NOOP", "PASV",
#	 "QUIT", "SITE", "PORT", "SYST", "STAT",
#	 "RMD", "MKD", "PWD", "STRU", "TYPE"] = 1,
#	["APPE", "LIST", "NLST", "RETR", "STOR", "STOU"] = 2,
#	["REIN"] = 3,
#	["RNFR", "RNTO"] = 4,
# };


function parse_ftp_reply_code(code: count): ftp_reply_code
	{
	local a: ftp_reply_code;

	a$z = code % 10;

	code = code / 10;
	a$y = code % 10;

	code = code / 10;
	a$x = code % 10;

	return a;
	}

event ftp_unexpected_conn_violation(id: conn_id, orig: addr, expected: addr)
	{
	NOTICE([$note=FTP_UnexpectedConn, $id=id,
		$msg=fmt("%s > %s FTP connection from %s",
			id$orig_h, id$resp_h, orig)]);
	}

event ftp_unexpected_conn(id: conn_id, orig: addr, expected: addr)
	{
	if ( orig in skip_unexpected || expected in skip_unexpected ||
	     mask_addr(orig, 24) in skip_unexpected_net ||
	     mask_addr(expected, 24) in skip_unexpected_net )
		; # don't bother reporting

	else if ( mask_addr(orig, 24) == mask_addr(expected, 24) )
		; # close enough, probably multi-homed

	else if ( mask_addr(orig, 16) == mask_addr(expected, 16) )
		; # ditto

	else
		event ftp_unexpected_conn_violation(id, orig, expected);
	}

event ftp_connection_expected(c: connection, orig_h: addr, resp_h: addr,
				resp_p: port, session: ftp_session_info)
	{
	}

event expected_connection_seen(c: connection, a: count)
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] in ftp_data_expected )
		add c$service["ftp-data"];
	}

# Deficiency: will miss data connections if the commands/replies
# are encrypted.
function is_ftp_data_conn(c: connection): bool
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] in ftp_data_expected )
		{
		local expected = ftp_data_expected[id$resp_h, id$resp_p];
		if ( id$orig_h != expected$host )
			event ftp_unexpected_conn(expected$session$connection_id,
				id$orig_h, expected$host);

		return T;
		}

	else if ( id$orig_p == 20/tcp &&
	          [$orig_h = id$resp_h, $orig_p = id$resp_p,
		   $resp_h = id$orig_h, $resp_p = 21/tcp] in ftp_sessions )
		return T;
	else
		return F;
	}


function new_ftp_session(c: connection, add_init: bool)
	{
	local session = c$id;
	local new_id = ++ftp_session_id;

	local info: ftp_session_info;
	info$id = new_id;
	info$connection_id = session;
	info$user = "<unknown>";
	info$anonymized_user = "<TBD!>";
	info$anonymous_login = T;
	info$request = "";
	info$num_requests = 0;
	info$request_t = c$start_time;
	info$log_if_not_unavail = F;
	info$log_if_not_denied = F;
	info$log_it = F;
	info$reply_code = 0;
	info$cwd = "<before_login>/";
	info$pending_requests = init_ftp_pending_cmds();

	if ( add_init )
		add_to_ftp_pending_cmds(info$pending_requests, "<init>", "");

	ftp_sessions[session] = info;
	append_addl(c, fmt("#%s", prefixed_id(new_id)));

	print log_file, fmt("%.6f #%s %s start", c$start_time, prefixed_id(new_id),
				id_string(session));
	}

function ftp_message(id: conn_id, msg: string)
	{
	print log_file, fmt("%.6f #%s %s",
			network_time(), prefixed_id(ftp_sessions[id]$id), msg);
	}

event ftp_sensitive_file(c: connection, session: ftp_session_info,
				filename: string)
	{
	session$log_if_not_unavail = T;
	}

event ftp_excessive_filename(session: ftp_session_info,
				command: string, arg: string)
	{
	NOTICE([$note=FTP_ExcessiveFilename, $id=session$connection_id,
		$user=session$user, $filename=arg,
		$msg=fmt("%s #%s excessive filename: %s",
				id_string(session$connection_id),
				prefixed_id(session$id), arg)]);
	session$log_it = T;
	}

global ftp_request_rewrite: function(c: connection, session: ftp_session_info,
					cmd_arg: ftp_cmd_arg);
global ftp_reply_rewrite: function(c: connection, session: ftp_session_info,
					code: count, msg: string,
					cont_resp: bool, cmd_arg: ftp_cmd_arg);

# Returns true if the given string is at least 25% composed of 8-bit
# characters.
function is_string_binary(s: string): bool
	{
	return byte_len(gsub(s, /[\x00-\x7f]/, "")) * 100 / byte_len(s) >= 25;
	}

event ftp_request(c: connection, command: string, arg: string)
	{
	# Command may contain garbage, e.g. if we're parsing something
	# which isn't ftp. Ignore this.
	if ( is_string_binary(command) )
		return;

	local id = c$id;

	if ( id !in ftp_sessions )
		new_ftp_session(c, F);

	local session = ftp_sessions[id];

	# Keep the original command and arg.
	local cmd_arg =
		add_to_ftp_pending_cmds(session$pending_requests, command, arg);

	if ( command == "USER" )
		{
		if ( arg in hot_ids &&
		     [id$orig_h, id$resp_h, arg] !in skip_hot )
			{
			if ( arg in always_hot_ids )
				session$log_it = T;
			else
				session$log_if_not_denied = T;
			}

		append_addl(c, arg);
		session$user = arg;

		if ( arg in forbidden_ids )
			TerminateConnection::terminate_connection(c);
		}

	else if ( command == "PASS" )
		{
		if ( session$user in forbidden_ids_if_no_password &&
		     arg == "" )
			TerminateConnection::terminate_connection(c);

		if ( session$user in guest_ids )
			append_addl_marker(c, arg, "/");
		else
			{
			event account_tried(c, session$user, arg);
			arg = "<suppressed>";
			}
		}

	else if ( command == "PORT" || command == "EPRT" )
		{
		local data = (command == "PORT") ?
				parse_ftp_port(arg) : parse_eftp_port(arg);

		if ( data$valid )
			{
			if ( data$h != id$orig_h )
				ftp_message(id, fmt("*> PORT host %s doesn't match originator host %s", data$h, id$orig_h));

			if ( data$p < 1024/tcp && data$p in port_names )
				NOTICE([$note=FTP_PrivPort, $id=id,
					$user=session$user,
					$msg=fmt("%s #%s privileged PORT %d: %s",
						id_string(id),
						prefixed_id(session$id),
						data$p, arg),
					$sub="PORT"]);

			local expected = [$host=c$id$resp_h, $session=session];
			ftp_data_expected[data$h, data$p] = expected;
			add session$expected[data$h, data$p];

			expect_connection(c$id$resp_h, data$h, data$p,
						ANALYZER_FILE, 5 min);

			event ftp_connection_expected(c, c$id$resp_h, data$h,
							data$p, session);
			}
		else if ( arg != ignore_invalid_PORT )
			NOTICE([$note=FTP_BadPort, $id=id,
				$user=session$user,
				$msg=fmt("%s #%s invalid ftp PORT directive: %s",
						id_string(id),
						prefixed_id(session$id), arg),
				$sub="PORT"]);
		}

	else if ( command in ftp_file_cmds )
		{
		if ( arg == hot_files ||
		     (session$user in guest_ids &&
		      arg == hot_guest_files) )
			event ftp_sensitive_file(c, session, arg);

		if ( byte_len(arg) >= excessive_filename_len )
			{
			arg = fmt("%s..[%d]..",
				sub_bytes(arg, 1, excessive_filename_trunc_len),
				byte_len(arg));
			event ftp_excessive_filename(session, command, arg);
			}
		}

	else if ( command == "ACCT" )
		append_addl(c, fmt("(account %s)", arg));

	if ( command in hot_cmds && arg == hot_cmds[command] )
		{
		session$log_it = T;

		# Special hack for "site exec" attacks.
		### Obviously, this should be generic and not specialized
		### like the following.
		if ( command == "SITE" && /[Ee][Xx][Ee][Cc]/ in arg &&
		     # We see legit use of "site exec cp / /", God knows why.
		     byte_len(arg) > 32 )
			{ # Terminate with extreme prejudice.
			TerminateConnection::terminate_connection(c);
			NOTICE([$note=FTP_SiteExecAttack, $conn=c, $conn=c, 
					$msg=fmt("%s %s", command, arg)]);
			}
		}

	local request = arg == "" ? command : cat(command, " ", arg);
	if ( ++session$num_requests == 1 )
		{
		# First pending request
		session$request = request;
		session$request_t = network_time();
		}
	else
		{
		# Don't append PASS commands, unless they're for an
		# anonymous user.

		### Is it okay to include the args of an ACCT command?

		if ( command == "PASS" )
			{
			if ( session$user in guest_ids )
				{
				session$request =
					cat(session$request, "/", arg);
				}

			# Don't count this as a multiple request.
			--session$num_requests;
			}
		else
			{
			if ( byte_len(session$request) < 256 )
				session$request = cat(session$request, ", ", request);
			}
		}

	if ( rewriting_ftp_trace )
		ftp_request_rewrite(c, session, cmd_arg);

	if ( command in ftp_all_cmds )
		{
		if ( command in ftp_untested_cmds )
			{
			delete ftp_untested_cmds[command];
			add ftp_first_seen_cmds[command];
			}
		}
	else
		add ftp_unlisted_cmds[command];
	}

event ftp_binary_response(session: ftp_session_info, code: count, msg: string)
	{
	print log_file, fmt("%.6f #%s binary response",
				network_time(), prefixed_id(session$id));
	}

function extract_dir_from_reply(session: ftp_session_info, msg: string,
				hint: string): string
	{
	const dir_pattern = /\"([^\"]|\"\")*(\/|\\)([^\"]|\"\")*\"/;
	local parts = split_all(msg, dir_pattern);

	if ( length(parts) != 3 )
		{ # not found or ambiguous
#		print log_file, fmt("%.6f #%s cannot extract directory: \"%s\"",
#			network_time(), prefixed_id(session$id), msg);
		return hint;
		}

	local d = parts[2];
	return sub_bytes(d, 2, int_to_count(byte_len(d) - 2));
	}

# Process ..'s and eliminate duplicate '/'s
# Deficiency: gives wrong results when a symbolic link is followed by ".."
function compress_path(dir: string): string
	{
	const cdup_sep = /((\/)+([^\/]|\\\/)+)?((\/)+\.\.(\/)+)/;

	local parts = split_n(dir, cdup_sep, T, 1);
	if ( length(parts) > 1 )
		{
		parts[2] = "/";
		dir = cat_string_array(parts);
		return compress_path(dir);
		}

	const multislash_sep = /(\/){2,}/;
	parts = split_all(dir, multislash_sep);
	for ( i in parts )
		if ( i % 2 == 0 )
			parts[i] = "/";
	dir = cat_string_array(parts);

	return dir;
	}

# Computes the absolute path with cwd (current working directory).
function absolute_path(session: ftp_session_info, file_name: string): string
	{
	local abs_file_name: string;
	if ( file_name == ftp_absolute_path_pat ) # start with '/' or 'A:\'
		abs_file_name = file_name;
	else
		abs_file_name = string_cat(session$cwd, "/", file_name);
	return  compress_path(abs_file_name);
	}

function do_ftp_reply(c: connection, session: ftp_session_info,
			code: count, msg: string, cmd: string, arg: string)
	{
	local id = c$id;

	if ( session$log_if_not_denied && code != 530 &&
	     # skip password prompt, which we can get when the requests
	     # are stacked up
	     code != 331 )
		session$log_it = T;

	if ( session$log_if_not_unavail && code != 550 )
		session$log_it = T;

	if ( code == 227  || code == 229 )
		{
		local data = (code == 227) ?
				parse_ftp_pasv(msg) : parse_ftp_epsv(msg);

		if ( code == 229 && data$h == 0.0.0.0 )
			data$h = id$resp_h;

		if ( data$valid )
			{
			if ( data$h != id$resp_h )
				ftp_message(id, fmt("*< PASV host %s doesn't match responder host %s", data$h, id$resp_h));

			if ( data$p < 1024/tcp && data$p in port_names &&
			     data$p !in ignore_privileged_PASVs )
				NOTICE([$note=FTP_PrivPort, $id=id,
					$user=session$user, $n=code,
					$msg=fmt("%s #%s privileged PASV %d: %s",
						id_string(id), prefixed_id(session$id),
						data$p, msg),
					$sub="PASV"]);

			local expected = [$host=id$orig_h, $session=session];
			ftp_data_expected[data$h, data$p] = expected;
			add session$expected[data$h, data$p];
			event ftp_connection_expected(c, c$id$orig_h, data$h,
							data$p, session);

			expect_connection(id$orig_h, data$h, data$p,
						ANALYZER_FILE, 5 min);

			msg = endpoint_id(data$h, data$p);
			}

		else if ( msg != ignore_invalid_PORT )
			{
			NOTICE([$note=FTP_BadPort, $id=id,
				$user=session$user, $n=code,
				$msg=fmt("%s #%s invalid ftp PASV directive: %s",
						id_string(id),
						prefixed_id(session$id), msg),
				$sub="PASV"]);
			msg = "invalid PASV";
			}
		}

	if ( [cmd, code] in ftp_dir_operation )
		{
		local cwd: string;

		if ( cmd == "CWD" )
			{
			if ( arg == ftp_absolute_path_pat ) # absolute dir
				cwd = arg;
			else
				cwd = cat(session$cwd, "/", arg);
			}

		else if ( cmd == "CDUP" )
			cwd = cat(session$cwd, "/..");

		else if ( cmd == "PWD" || cmd == "XPWD" )
			# Here we need to guess how to extract the
			# directory from the reply.
			cwd = extract_dir_from_reply(session, msg,
							 session$cwd);

		# cwd = cat(cwd, "/");

		# Process "..", eliminate duplicate '/'s, and eliminate
		# last '/' if cwd != "/"
		# session$cwd = compress_path(cwd);

		session$cwd = cwd;

#		print log_file, fmt("*** DEBUG *** %.06f #%s (%s %s) CWD = \"%s\"",
#				network_time(), prefixed_id(session$id),
#				cmd, arg, session$cwd);
		}

	if ( session$num_requests > 0 )
		{
		if ( code in ftp_skip_replies )
			;	# Don't flush request yet.

		else
			{
			local reply = code in ftp_replies ? ftp_replies[code] :
					fmt("%d %s", code, msg);

			local session_msg = fmt("#%s %s%s (%s)",
					prefixed_id(session$id),
					session$num_requests > 1 ? "*" : "",
					session$request, reply);

			if ( session$log_it )
				NOTICE([$note=FTP_Sensitive, $id=id,
					$user=session$user, $n=code,
					$msg=fmt("ftp: %s %s",
						id_string(id), session_msg)]);

			print log_file, fmt("%.6f %s", session$request_t,
						session_msg);

			session$request = "";
			session$num_requests = 0;
			session$log_if_not_unavail = F;
			session$log_if_not_denied = F;
			session$log_it = F;
			}
		}
	else
		{
		# An unpaired response.  This can happen in particular
		# when the session is encrypted, so we check for that here.
		if ( /[\x80-\xff]{3}/ in msg )
			# Three 8-bit characters in a row - good enough.
			# Note, this should of course be customizable.
			event ftp_binary_response(session, code, msg);

		else
			print log_file, fmt("%.6f #%s response (%d %s)",
					network_time(), prefixed_id(session$id), code, msg);
		}
	}

function do_ftp_login(c: connection, session: ftp_session_info)
	{
	session$cwd = ftp_init_dir[session$connection_id$resp_h, session$user];
	event login_successful(c, session$user);
	}

event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
	{
	local id = c$id;
	local response_xyz = parse_ftp_reply_code(code);

	if ( id !in ftp_sessions )
		new_ftp_session(c, T);

	local session = ftp_sessions[id];

	if ( code != 0 || ! cont_resp )
		session$reply_code = code;

	local cmd_arg = find_ftp_pending_cmd(session$pending_requests, session$reply_code, msg);

	if ( ! cont_resp )
		{
		if ( response_xyz$x == 2 &&	# successful
		     (cmd_arg$cmd == /USER|PASS|ACCT/) )
			do_ftp_login(c, session);

		do_ftp_reply(c, session, code, msg, cmd_arg$cmd, cmd_arg$arg);
		}

	if ( rewriting_ftp_trace )
		{
		ftp_reply_rewrite(c, session, code, msg, cont_resp, cmd_arg);
		}

	if ( ! cont_resp )
		{
		if ( ftp_cmd_pending(session$pending_requests) )
			{
			if ( response_xyz$x == 1 )
				# nothing
				;

			else if ( response_xyz$x >= 2 && response_xyz$x <= 5 )
				{
				pop_from_ftp_pending_cmd(session$pending_requests, cmd_arg);
				# print log_file, fmt("*** DEBUG *** %.06f #%d: [%s %s] [%d %s]",
				#	network_time(), session$id, cmd_arg$cmd, cmd_arg$arg, code, msg);
				}
			}

		else if ( code != 421 ) # closing connection
			ftp_message(id, fmt("spontaneous response (%d %s)",
					code, msg));
		}
	}

const call_ftp_connection_remove = F &redef;
global ftp_connection_remove: function(c: connection);

# Use state remove event instead of finish to cover connections terminated by
# RST.
event connection_state_remove(c: connection)
	{
	local id = c$id;

	if ( is_ftp_conn(c) && call_ftp_connection_remove )
		ftp_connection_remove(c);

	if ( id in ftp_sessions )
		{
		local session = ftp_sessions[id];

		if ( session$num_requests > 0 )
			{
			local msg = fmt("#%s %s%s (no reply)",
					prefixed_id(session$id),
					session$num_requests > 1 ? "*" : "",
					session$request);

			if ( session$log_it )
				NOTICE([$note=FTP_Sensitive, $id=id,
					$user=session$user,
					$msg=fmt("ftp: %s %s",
						id_string(id), msg)]);

			print log_file, fmt("%.6f %s", session$request_t, msg);
			}

		if ( ftp_cmd_pending(session$pending_requests) )
			{
			local ca = find_ftp_pending_cmd(session$pending_requests, 0, "<finish>");
			# print log_file, fmt("*** DEBUG *** requests pending from %s %s", ca$cmd, ca$arg);
			}

		for ( [h, p] in session$expected )
			delete ftp_data_expected[h, p];

		ftp_message(id, "finish");

		delete ftp_sessions[id];
		}
	}

event file_transferred(c: connection, prefix: string, descr: string,
			mime_type: string)
	{
	if ( [c$id$resp_h, c$id$resp_p] in ftp_data_expected )
		{
		local expected = ftp_data_expected[c$id$resp_h, c$id$resp_p];
		print log_file, fmt("%.6f #%s ftp-data %s '%s'",
					c$start_time,
					prefixed_id(expected$session$id),
					mime_type, descr);
		append_addl(c, descr);
		}
	}

event file_virus(c: connection, virname: string)
	{
	if ( [c$id$resp_h, c$id$resp_p] in ftp_data_expected )
		{
		local expected = ftp_data_expected[c$id$resp_h, c$id$resp_p];
		# FIXME: Throw NOTICE.
		print log_file, fmt("%.6f #%s VIRUS %s found", c$start_time,
					prefixed_id(expected$session$id),
					virname);
		append_addl(c, fmt("Virus %s", virname));
		}
	}

event bro_init()
	{
	have_FTP = T;
	}
