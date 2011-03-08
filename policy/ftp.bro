@load functions
@load notice.bro
@load ftp-cmd-arg

#@load conn
#@load scan
#@load hot-ids
#@load terminate-connection

module FTP;

redef enum Notice::Type += {
	FTP_UnexpectedConn,     # FTP data transfer from unexpected src
	FTP_ExcessiveFilename,  # very long filename seen
	FTP_PrivPort,           # privileged port used in PORT/PASV;
	                        #   $sub says which
	FTP_BadPort,            # bad format in PORT/PASV; $sub says which
	FTP_Sensitive,          # sensitive connection - not more specific
	FTP_SiteExecAttack,     # specific "site exec" attack seen
};


export {
	redef enum Log::ID += { FTP_AUTH, FTP_FILES };
	type LogFiles: record {
		ts:         time;
		id:         conn_id;
		user:       string &default="";
		password:   string &optional;
		command:    string &default="";
		url:        string &default="";
		mime_type:  string &default="";
		mime_desc:  string &default="";
		reply_code: count  &default=0;
		reply_msg:  string &default="";
	};
	
	type SessionInfo: record {
		ts:                 time;               # time of request
		id:                 conn_id;
		user:               string &default="<unknown>";
		password:           string &optional;
		cwd:                string &default="<before_login>/";
		command:            CmdArg &optional;
		reply_code:         count &default=0;   # the most recent reply code
		reply_msg:          string &default=""; # the most recent reply message
		
		pending_commands:   PendingCmds;        # pending requests
		
		log_it:             bool &default=F;    # if true, log the request(s)s
	};

	type FTPExpectedConn: record {
		host:    addr;
		session: SessionInfo;
	};
	
	type ReplyCode: record {
		x: count;	# high-order (3rd digit)
		y: count;	# middle (2nd) digit
		z: count;	# bottom digit
	};
	

	# Indexed by source & destination addresses and the id.
	#const skip_hot: set[addr, addr, string] &redef;

   # see: http://packetstormsecurity.org/UNIX/penetration/rootkits/index4.html
   # for current list of rootkits to include here

	#const hot_files =
	#	  /.*(etc\/|master\.)?(passwd|shadow|s?pwd\.db)/
	#	| /.*snoop\.(tar|tgz).*/
	#	| /.*bnc\.(tar|tgz).*/
	#	| /.*datapipe.*/
	#	| /.*ADMw0rm.*/
	#	| /.*newnick.*/
	#	| /.*sniffit.*/
	#	| /.*neet\.(tar|tgz).*/
	#	| /.*\.\.\..*/
	#	| /.*ftpscan.txt.*/
	#	| /.*jcc.pdf.*/
	#	| /.*\.[Ff]rom.*/
	#	| /.*sshd\.(tar|tgz).*/
	#	| /.*\/rk7.*/
	#	| /.*rk7\..*/
	#	| /.*[aA][dD][oO][rR][eE][bB][sS][dD].*/
	#	| /.*[tT][aA][gG][gG][eE][dD].*/
	#	| /.*shv4\.(tar|tgz).*/
	#	| /.*lrk\.(tar|tgz).*/
	#	| /.*lyceum\.(tar|tgz).*/
	#	| /.*maxty\.(tar|tgz).*/
	#	| /.*rootII\.(tar|tgz).*/
	#	| /.*invader\.(tar|tgz).*/
	#&redef;

	#const hot_guest_files =
	#	  /.*\.rhosts/
	#	| /.*\.forward/
	#	&redef;

	#const hot_cmds: table[string] of pattern = {
	#	["SITE"] = /[Ee][Xx][Ee][Cc].*/,
	#} &redef;

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

	# This tracks all of the currently established FTP control sessions.
	global ftp_sessions: table[conn_id] of SessionInfo;
	
	# Indexed by the responder pair, yielding the address expected to connect to it.
	global ftp_data_expected: table[addr, port] of FTPExpectedConn &create_expire=1min;
		
	global ftp_ports = { 21/tcp } &redef; 
	redef dpd_config += { [ANALYZER_FTP] = [$ports = ftp_ports] };
	redef capture_filters += { ["ftp"] = "port 20 or port 21" };
}

event bro_init()
	{
	Log::create_stream("FTP_FILES", "FTP::LogFiles");
	Log::add_default_filter("FTP_FILES");
	}

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


# const ftp_state_diagram: table[string] of count = {
#	["ABOR", "ALLO", "DELE", "CWD", "CDUP",
#	 "SMNT", "HELP", "MODE", "NOOP", "PASV",
#	 "QUIT", "SITE", "PORT", "SYST", "STAT",
#	 "RMD", "MKD", "PWD", "STRU", "TYPE"] = 1,
#	["APPE", "LIST", "NLST", "RETR", "STOR", "STOU"] = 2,
#	["REIN"] = 3,
#	["RNFR", "RNTO"] = 4,
# };

function cmd_pending(s: SessionInfo): bool
	{
	return |s$pending_commands| > 0;
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
function absolute_path(session: SessionInfo, file_name: string): string
	{
	local abs_file_name: string;
	if ( file_name == ftp_absolute_path_pat ) # start with '/' or 'A:\'
		abs_file_name = file_name;
	else
		abs_file_name = string_cat(session$cwd, "/", file_name);
	return compress_path(abs_file_name);
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

	#else
	#	Notice::NOTICE([$note=FTP_UnexpectedConn, $id=id,
	#		$msg=fmt("%s > %s FTP connection from %s",
	#			id$orig_h, id$resp_h, orig)]);
	}

event expected_connection_seen(c: connection, a: count)
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] in ftp_data_expected )
		{
		add c$service["ftp-data"];
		delete ftp_data_expected[id$resp_h, id$resp_p];
		}
	}

function new_ftp_session(c: connection, add_init: bool)
	{
	local id = c$id;

	local info: SessionInfo;
	info$id = id;
	local cmds: table[count] of CmdArg = table();
	info$pending_commands = cmds;
	
	if ( add_init )
		add_pending_cmd(info$pending_commands, "<init>", "");

	ftp_sessions[id] = info;
	
	#append_addl(c, fmt("#%s", prefixed_id(new_id)));

	#print log_file, fmt("%.6f #%s %s start", c$start_time, prefixed_id(new_id),
	#			id_string(session));
	}

function ftp_message(s: SessionInfo)
	{
	if ( !s$log_it ) return;
	
	local pass = "";
	if ( s$user in guest_ids && s?$password )
		pass = s$password;
	local pathfile = sub(absolute_path(s, s$command$arg), /<unknown>/, "/.");
	
	if ( s$command$cmd in ftp_file_cmds )
	Log::write("FTP_FILES", [$ts=network_time(), $id=s$id,
	                         $user=s$user, $password=pass,
	                         $command=s$command$cmd,
	                         $url=fmt("ftp://%s%s", s$id$resp_h, pathfile),
	                         $mime_type="", $mime_desc="",
	                         $reply_code=s$reply_code, $reply_msg=s$reply_msg]);
	s$log_it = F;
	}

event ftp_request(c: connection, command: string, arg: string)
	{
	local id = c$id;
	
	# Command may contain garbage, e.g. if we're parsing something
	# which isn't ftp. Ignore this.
	if ( is_string_binary(command) )
		return;

	if ( id !in ftp_sessions )
		new_ftp_session(c, F);
	local session = ftp_sessions[id];

	# Queue up the command and argument
	add_pending_cmd(session$pending_commands, command, arg);
	
	if ( command == "USER" )
		session$user = arg;
	
	else if ( command == "PASS" )
		session$password = arg;
	
	else if ( command in ftp_file_cmds )
		{
		if ( |arg| >= excessive_filename_len )
			{
			arg = fmt("%s..[%d]..",
				sub_bytes(arg, 1, excessive_filename_trunc_len), |arg|);
			#Notice::NOTICE([$note=FTP_ExcessiveFilename, $id=session$id,
			#                #$user=session$user, $filename=arg,
			#                $msg=fmt("%s excessive filename: %s",
			#                         id_string(session$id), arg)]);
			}
		}

	else if ( command == "ACCT" )
		append_addl(c, fmt("(account %s)", arg));
		
	else if ( command == "PORT" || command == "EPRT" )
		{
		local data = (command == "PORT") ?
				parse_ftp_port(arg) : parse_eftp_port(arg);

		if ( data$valid )
			{
			#if ( data$h != id$orig_h )
			#	ftp_message(id, fmt("*> PORT host %s doesn't match originator host %s", data$h, id$orig_h));

			#if ( data$p < 1024/tcp && data$p in port_names )
			#	Notice::NOTICE([$note=FTP_PrivPort, $id=id,
			#	                $user=session$user,
			#	                $msg=fmt("%s privileged PORT %d: %s",
			#	                         id_string(id),data$p, arg),
			#	                $sub="PORT"]);

			local expected = [$host=c$id$resp_h, $session=session];
			ftp_data_expected[data$h, data$p] = expected;

			expect_connection(c$id$resp_h, data$h, data$p,
						ANALYZER_FILE, 5 min);
			}
		#else if ( arg != ignore_invalid_PORT )
		#	Notice::NOTICE([$note=FTP_BadPort, $id=id,
		#	                #$user=session$user,
		#	                $msg=fmt("%s invalid ftp PORT directive: %s",
		#	                         id_string(id), arg),
		#	                $sub="PORT"]);
		}


	#if ( command in hot_cmds && arg == hot_cmds[command] )
	#	{
	#	session$log_it = T;

		# TODO: generate a notice instead of terminating here.
		# Special hack for "site exec" attacks.
		### Obviously, this should be generic and not specialized
		### like the following.
		#if ( command == "SITE" && /[Ee][Xx][Ee][Cc]/ in arg &&
		#     # We see legit use of "site exec cp / /", God knows why.
		#     |arg| > 32 )
		#	{ # Terminate with extreme prejudice.
		#	TerminateConnection::terminate_connection(c);
		#	Notice::NOTICE([$note=FTP_SiteExecAttack, $conn=c, $conn=c, 
		#	                $msg=fmt("%s %s", command, arg)]);
		#	}
	#	}
	}

event ftp_binary_response(session: SessionInfo, code: count, msg: string)
	{
	#print log_file, fmt("%.6f #%s binary response",
	#			network_time(), prefixed_id(session$id));
	}

function extract_dir_from_reply(session: SessionInfo, msg: string,
				hint: string): string
	{
	const dir_pattern = /\"([^\"]|\"\")*(\/|\\)([^\"]|\"\")*\"/;
	local parts = split_all(msg, dir_pattern);

	if ( |parts| != 3 )
		{ # not found or ambiguous
#		print log_file, fmt("%.6f #%s cannot extract directory: \"%s\"",
#			network_time(), prefixed_id(session$id), msg);
		return hint;
		}

	local d = parts[2];
	return sub_bytes(d, 2, int_to_count(|d| - 2));
	}

function do_ftp_login(c: connection, session: SessionInfo)
	{
	#event login_successful(c, session$user);
	}

event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
	{
	# Not sure how to handle multiline responses yet.
	if ( cont_resp ) return;
		
	local id = c$id;
	if ( id !in ftp_sessions )
		new_ftp_session(c, T);
	local session = ftp_sessions[id];

	session$reply_code = code;
	session$reply_msg = msg;
	
	local cmd_arg = get_pending_cmd(session$pending_commands, code, msg);
	local response_xyz = parse_ftp_reply_code(code);
	
	#if ( response_xyz$x == 2 &&  # successful
	#     (cmd_arg$cmd == /USER|PASS|ACCT/) )
	#	do_ftp_login(c, session);

	# skip password prompt, which we can get when the requests are stacked up
	if ( code != 530 && code != 331 )
		session$log_it = T;

	if ( code == 227  || code == 229 )
		{
		local data = (code == 227) ? parse_ftp_pasv(msg) : parse_ftp_epsv(msg);

		if ( code == 229 && data$h == 0.0.0.0 )
			data$h = id$resp_h;

		if ( data$valid )
			{
			#if ( data$h != id$resp_h )
			#	ftp_message(id, fmt("*< PASV host %s doesn't match responder host %s", data$h, id$resp_h));

			#if ( data$p < 1024/tcp &&
			#     data$p !in ignore_privileged_PASVs )
			#	Notice::NOTICE([$note=FTP_PrivPort, $id=id,
			#	                $msg=fmt("%s privileged PASV %d: %s",
			#	                         id_string(id), data$p, msg),
			#	                $n=code, $sub="PASV"]);

			local expected = [$host=id$orig_h, $session=session];
			ftp_data_expected[data$h, data$p] = expected;
			expect_connection(id$orig_h, data$h, data$p, ANALYZER_FILE, 5 min);

			msg = fmt("%s %d", data$h, data$p);
			}

		else if ( msg != ignore_invalid_PORT )
			{
			#Notice::NOTICE([$note=FTP_BadPort, $id=id,
			#                $msg=fmt("%s invalid ftp PASV directive: %s",
			#                         id_string(id), msg),
			#                $sub="PASV", $n=code]);
			msg = "invalid PASV";
			}
		}

	if ( [cmd_arg$cmd, code] in ftp_dir_operation )
		{
		local cwd: string;

		if ( cmd_arg$cmd == "CWD" )
			{
			if ( cmd_arg$arg == ftp_absolute_path_pat ) # absolute dir
				cwd = cmd_arg$arg;
			else
				cwd = cat(session$cwd, "/", cmd_arg$arg);
			}

		else if ( cmd_arg$cmd == "CDUP" )
			cwd = cat(session$cwd, "/..");

		else if ( cmd_arg$cmd == "PWD" || cmd_arg$cmd == "XPWD" )
			# Here we need to guess how to extract the
			# directory from the reply.
			cwd = extract_dir_from_reply(session, msg, session$cwd);

		session$cwd = cwd;
		}

	if ( cmd_pending(session) )
		{
		if ( code in ftp_skip_replies )
			;	# Don't flush request yet.

		else
			{
			local reply = code in ftp_replies ? ftp_replies[code] :
					fmt("%d %s", code, msg);

			#local session_msg = fmt("%s%s (%s)",
			#                        |session$pending_commands| > 1 ? "*" : "",
			#                        session$command, reply);
            #
			#if ( session$log_it )
			#	Notice::NOTICE([$note=FTP_Sensitive, $id=id, $n=code,
			#	                $msg=fmt("ftp: %s %s",
			#	                         id_string(id), session_msg)]);

			#ftp_message(id, "whatever");

			#session$command = "";
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
			print fmt("Saw an unpaired response %d %s", code, msg);
			#print log_file, fmt("%.6f #%s response (%d %s)",
			#		network_time(), prefixed_id(session$id), code, msg);
		}

	#if ( cmd_pending(session) )
	#	{
	#	if ( response_xyz$x == 1 )
	#		# nothing
	#		;
    #
	#	else if ( response_xyz$x >= 2 && response_xyz$x <= 5 )
	#		{
	#		remove_pending_cmd(session$pending_commands, cmd_arg);
	#		# print log_file, fmt("*** DEBUG *** %.06f #%d: [%s %s] [%d %s]",
	#		#	network_time(), session$id, cmd_arg$cmd, cmd_arg$arg, code, msg);
	#		}
	#	}
	
	session$command = pop_pending_cmd(session$pending_commands, code, msg);
	# Go ahead and log for the oldest command.
	ftp_message(session);

	#else if ( code != 421 ) # closing connection
	#	ftp_message(id, fmt("spontaneous response (%d %s)", code, msg));
	}

# Use state remove event instead of finish to cover connections terminated by
# RST.
event connection_state_remove(c: connection)
	{
	local id = c$id;
	if ( id !in ftp_sessions )
		return;

	local session = ftp_sessions[id];

	if ( cmd_pending(session) )
		{
		#local msg = fmt("%s%s (no reply)",
		#                |session$pending_commands| > 1 ? "*" : "",
		#                session$command);
        #
		#if ( session$log_it )
		#	Notice::NOTICE([$note=FTP_Sensitive, $id=id,
		#	                $msg=fmt("ftp: %s %s", id_string(id), msg)]);
		
		local ca = get_pending_cmd(session$pending_commands, 0, "<finish>");
		}

	#ftp_message(id, "finish");

	delete ftp_sessions[id];
	}

event file_transferred(c: connection, prefix: string, descr: string,
			mime_type: string)
	{
	if ( [c$id$resp_h, c$id$resp_p] in ftp_data_expected )
		{
		local expected = ftp_data_expected[c$id$resp_h, c$id$resp_p];
		print fmt("%.6f ftp-data %s '%s'",
					c$start_time,
					mime_type, descr);
		#append_addl(c, descr);
		}
	}

