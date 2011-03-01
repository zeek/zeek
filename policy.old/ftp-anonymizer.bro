# $Id: ftp-anonymizer.bro 47 2004-06-11 07:26:32Z vern $

@load ftp
@load anon

# Definitions of constants.

# Check if those commands carry any argument; anonymize non-empty
# argument.
const ftp_cmds_with_no_arg = {
	"CDUP", "QUIT", "REIN", "PASV", "STOU",
	"ABOR", "PWD", "SYST", "NOOP",

	"FEAT",	"XPWD",
};

const ftp_cmds_with_file_arg = {
	"APPE", "CWD", "DELE", "LIST", "MKD",
	"NLST", "RMD", "RNFR", "RNTO", "RETR",
	"STAT", "STOR", "SMNT",
	# FTP extensions
	"SIZE", "MDTM",
	"MLSD", "MLST",
	"XCWD",
};

# For following commands, we check if the argument conforms to the
# specification -- if so, it is safe to be left in the clear.
const ftp_cmds_with_safe_arg = {
	"TYPE", "STRU", "MODE", "ALLO", "REST",
	"HELP",

	"MACB",	# MacBinary encoding
};

# ftp_other_cmds can be redefined in site/trace-specific ways.
const ftp_other_cmds = {
	"LPRT", "OPTS", "CLNT", "RETP",
	"EPSV", "XPWD",
	"SOCK",	# old FTP command (RFC 354)
} &redef;

# Below defines patterns of arguments of FTP commands

# The following patterns are case-insensitive
const ftp_safe_cmd_arg_pattern =
	  /TYPE (([AE]( [NTC])?)|I|(L [0-9]+))/
	| /STRU [FRP]/
	| /MODE [SBC]/
	| /ALLO [0-9]+([ \t]+R[ \t]+[0-9]+)?/
	| /REST [!-~]+/
	| /MACB (E|DISABLE|ENABLE)/
	| /SITE TRUTH ON/
	&redef;

# The following list includes privacy-safe [cmd, arg] pairs and can be
# customized for particular traces
const ftp_safe_arg_list: set[string, string] = {
} &redef;

# ftp_special_cmd_args offers an even more flexible way of customizing
# argument anonymization: for each [cmd, arg] pair in the table, the
# corresponding value will be the anonymized argument.
const ftp_special_cmd_args: table[string, string] of string = {
} &redef;

# The following words are safe to be left in the clear as the argument
# of a HELP command.
const ftp_help_words = {
	"USER",	"PORT",	"STOR",	"MSAM",	"RNTO",	"NLST",	"MKD",	"CDUP",
	"PASS",	"PASV",	"APPE",	"MRSQ",	"ABOR",	"SITE",	"XMKD",	"XCUP",
	"ACCT",	"TYPE",	"MLFL",	"MRCP",	"DELE",	"SYST",	"RMD",	"STOU",
	"SMNT",	"STRU",	"MAIL",	"ALLO",	"CWD",	"STAT",	"XRMD",	"SIZE",
	"REIN",	"MODE",	"MSND",	"REST",	"XCWD",	"HELP",	"PWD",	"MDTM",
	"QUIT",	"RETR",	"MSOM",	"RNFR",	"LIST",	"NOOP",	"XPWD",
} &redef;

const ftp_port_pat = /[0-9]+([[:blank:]]*,[[:blank:]]*[0-9]+){5}/;

# Pattern for the argument of EPRT command.
# TODO: the pattern works fot the common case but is not RFC2428-complete.
const ftp_eprt_pat = /\|1\|[0-9]{1,3}(\.[0-9]{1,3}){3}\|[0-9]{1,5}\|/;

# IP addresses.
const ftp_ip_pat = /[0-9]{1,3}(\.[0-9]{1,3}){3}/;

# Domain names (deficiency: domain suffices of countries).
const ftp_domain_name_pat =
	/([\-0-9a-zA-Z]+\.)+(com|edu|net|org|gov|mil|uk|fr|nl|es|jp|it)/;

# File names (printable characters).
const ftp_file_name_pat = /[[:print:]]+/;

# File names that can be left in the clear.
const ftp_public_files =
	  /\// | /\.\./		# "/" and ".."
	| /(\/etc\/|master\.)?(passwd|shadow|s?pwd\.db)/ # ftp_hot_files
	| /\/(etc|usr\/bin|bin|sbin|kernel)(\/)?/
	| /\.rhosts/ | /\.forward/			 # ftp_hot_guest_files
&redef;

const ftp_sensitive_files =
	  /.*(etc\/|master\.)?(passwd|shadow|s?pwd\.db)/ # ftp_hot_files
	| /\/(etc|usr\/bin|bin|sbin|kernel)\/.*/
	| /.*\.rhosts/ | /.*\.forward/			 # ftp_hot_guest_files
&redef;

# Public servers.
const ftp_public_servers: set[addr] = {} &redef;

# Whether we keep all file names (valid or invalid) for public servers.
const ftp_keep_all_files_for_public_servers = F &redef;

# Public files.
const ftp_known_public_files: set[addr, string] = {} &redef;

# Hidden file/directory.
const ftp_hidden_file = /.*\/\.[^.\/].*/;
const ftp_public_hidden_file = /0/ &redef;

# Options for file commands (LIST, NLST) that can be left in the clear.
const ftp_known_option = /-[[:alpha:]]{1,5}[ ]*/;

const ftp_known_site_cmd = {
	"UMASK", "GROUP", "INDEX", "GROUPS",
	"IDLE", "GPASS", "EXEC", "CHECKMETHOD",
	"CHMOD", "NEWER", "ALIAS", "CHECKSUM",
	"HELP", "MINFO", "CDPATH",

	"TRUTH", "UTIME",
} &redef;

const ftp_sensitive_ids: set[string] = {
	"backdoor", "bomb", "diag", "gdm", "issadmin", "msql", "netfrack",
	"netphrack", "own", "r00t", "root", "ruut", "smtp", "sundiag", "sync",
	"sys", "sysadm", "sysdiag", "sysop", "sysoper", "system", "toor", "tour",
	"y0uar3ownd",
};

redef anonymize_ip_addr = T;
redef rewriting_ftp_trace = T;

global ftp_anon_log = open_log_file("ftp-anon") &redef;

# Anonymized arguments, indexed by the anonymization seed.
global anonymized_args: table[string] of string;

# Arguments left in the clear, indexed by the argument and the context.
global ftp_arg_left_in_the_clear: set[string, string];

# Valid files on public servers.
global ftp_valid_public_files: set[addr, string];

type ftp_cmd_arg_anon_result: record {
	anonymized: bool;
	cmd: string;
	arg: string;
};


# Whether anonymize_trace_specific_cmd_arg is defined:
const trace_specific_cmd_arg_anonymization = F &redef;

# This function is to be defined in a trace-specific script. By
# default, use ftp-anonymizer-trace.bro.

global anonymize_trace_specific_cmd_arg:
	function(session: ftp_session_info, cmd: string, arg: string):
		ftp_cmd_arg_anon_result;


# Anonymize FTP replies by message patterns.
const process_ftp_reply_by_message_pattern = F &redef;
global anonymize_ftp_reply_by_msg_pattern:
	function(code: count, act_msg: string,
		cmd_arg: ftp_cmd_arg, session: ftp_session_info): string;


# Anonymize an argument *completely* with a hash value of the string,
# and log the anonymization.
function anonymize_arg(typ: string, session: ftp_session_info, cmd: string, arg: string, seed: string): string
	{
	if ( arg == "" )
		return ""; # an empty argument is safe

	local arg_seed = string_cat(typ, seed, arg);

	if ( arg_seed in anonymized_args )
		return anonymized_args[arg_seed];

	local a = anonymize_string(arg_seed);
	anonymized_args[arg_seed] = a;

	print ftp_anon_log,
		fmt("anonymize_arg: (%s) {%s} %s \"%s\" to \"%s\" in [%s]",
				typ, seed, cmd,
				to_string_literal(arg), to_string_literal(a),
				id_string(session$connection_id));
	return a;
	}

# This function is called whenever an argument is to be left in the
# clear. It logs the action if it hasn't occurred before.
function leave_in_the_clear(msg: string, session: ftp_session_info,
				arg: string, context: string): string
	{
	if ( [arg, context] !in ftp_arg_left_in_the_clear )
		{
		add ftp_arg_left_in_the_clear[arg, context];
		print ftp_anon_log, fmt("leave_in_the_clear: (%s) \"%s\" [%s] in [%s]",
				msg, to_string_literal(arg), context,
				id_string(session$connection_id));
		}
	return arg;
	}


# Sometimes the argument of a file command contains an option string
# before the file name, such as in 'LIST -l /xyz/', the following
# function identifies such option strings and separate the argument
# accordingly.

type separate_option_str_result: record {
	opt_str: string;
	file_name: string;
};

function separate_option_str(file_name: string): separate_option_str_result
	{
	local ret: separate_option_str_result;
	if ( file_name == /-[[:alpha:]]+( .*)?/ )
		{
		local parts = split_all(file_name, /-[[:alpha:]]+[ ]*/);
		ret$opt_str = string_cat(parts[1], parts[2]);
		parts[1] = ""; parts[2] = "";
		ret$file_name = cat_string_array(parts);
		return ret;
		}
	else
		return [$opt_str = "", $file_name = file_name];
	}


# Anonymize a user id
type login_status_type: enum {
	LOGIN_PENDING,
	LOGIN_SUCCESSFUL,
	LOGIN_FAILED,
	LOGIN_UNKNOWN,
};

function anonymize_user_id(session: ftp_session_info, id: string, login_status: login_status_type, msg: string): string
	{
	if ( id in ftp_guest_ids )
		{
		leave_in_the_clear("guest_id", session, id, msg);
		return id;
		}

	else if ( id in ftp_sensitive_ids && login_status == LOGIN_FAILED )
		{
		leave_in_the_clear("sensitive_id", session, id, msg);
		return id;
		}

	else
		return anonymize_arg("user_name", session, "USER", id, cat(session$connection_id$resp_h, login_status));
	}

# Anonymize a file name argument.
function anonymize_file_name_arg(session: ftp_session_info, cmd: string, arg: string, valid_file_name: bool): string
	{
	local file_name = arg;
	local opt_str = "";
	if ( cmd == /LIST|NLST/ )
		{
		# Separate the option from file name if there is one

		local ret = separate_option_str(file_name);
		if ( ret$opt_str != "" )
			{
			opt_str = ret$opt_str;

			# Shall we anonymize the option string?
			if ( opt_str != ftp_known_option )
				{
				# Anonymize the option conservatively
				print ftp_anon_log, fmt("option_anonymized: \"%s\" from (%s %s)",
					to_string_literal(opt_str), cmd, file_name);
				opt_str = "-<option>";
				}
			else
				# Leave in the clear
				print ftp_anon_log, fmt("option_left_in_the_clear: \"%s\" from (%s %s)",
					to_string_literal(opt_str), cmd, file_name);

			file_name = ret$file_name;
			}
		}

	if ( file_name == "" )
		return opt_str;

	if ( file_name != ftp_file_name_pat )
		{
		# Log special file names (e.g. those containing
		# control characters) for manual inspection -- such
		# file names are rare and may present problems in
		# reply anonymization.

		print ftp_anon_log, fmt("unrecognized_file_name: \"%s\" (%s) [%s]",
			to_string_literal(file_name), cmd, id_string(session$connection_id));
		}


	if ( strstr(file_name, " ") > 0 )
		{
		# Log file names that contain spaces (for debugging only)

		print ftp_anon_log, fmt("space_in_file_name: \"%s\" (%s) [%s]",
			to_string_literal(file_name), cmd, id_string(session$connection_id));
		}

	# Compute the absolute and clean (without '..' and duplicate
	# '/') path
	local abs_path = absolute_path(session, file_name);
	local resp_h = session$connection_id$resp_h;
	local known_public_file =
		[resp_h, abs_path] in ftp_known_public_files ||
		[resp_h, abs_path] in ftp_valid_public_files;

	if ( file_name == ftp_public_files || abs_path == ftp_public_files )
		{
		leave_in_the_clear("public_path_name", session,
			arg, fmt("(%s %s) %s", cmd, file_name, abs_path));
		}

	else if ( resp_h in ftp_public_servers &&
		  (abs_path != ftp_hidden_file ||
		   abs_path == ftp_public_hidden_file) &&
		  (ftp_keep_all_files_for_public_servers || valid_file_name ||
		   known_public_file) )
		{
		if ( valid_file_name && ! known_public_file )
			{
			add ftp_valid_public_files[resp_h, abs_path];
			print ftp_anon_log,
				fmt("valid_public_file: [%s, \"%s\"]",
					resp_h, to_string_literal(abs_path));
			}

		leave_in_the_clear("file_on_public_server", session, arg,
			fmt("%s %s:%s", cmd, session$connection_id$resp_h, abs_path));
		}
	else
		{
		local anon_type: string;

		if ( file_name == ftp_sensitive_files ||
		     abs_path == ftp_sensitive_files )
			anon_type = "sensitive_path_name";

		else if ( abs_path == ftp_hidden_file )
			anon_type = "hidden_path_name";

		else if ( resp_h in ftp_public_servers )
			anon_type = "invalid_public_file";

		else
			anon_type = "path_name";

		file_name = anonymize_arg(anon_type, session, cmd, abs_path, cat("file:", session$connection_id$resp_h));
		}

	# concatenate the option string with the file_name
	return string_cat(opt_str, file_name);
	}


# The argument is presumably privacy-safe, but we should not assume
# that it is the case. Instead, we check if the argument is legal and
# thus privacy-free.
function check_safe_arg(session: ftp_session_info, cmd: string,
			arg: string): string
	{
	if ( cmd == "HELP" )
		return ( arg in ftp_help_words ) ?
				leave_in_the_clear("known_help_word", session,
					arg,
					fmt("%s %s", cmd, arg))
				: anonymize_arg("unknown_help_string", session, cmd, arg, cmd);

	else
		# Note that we have already checked the (cmd, arg)
		# against ftp_safe_cmd_arg_pattern. So the argument
		# here must have an unrecognized pattern and should be
		# anonymized.
		return anonymize_arg("illegal_argument", session, cmd, arg, cmd);
	}

function check_site_arg(session: ftp_session_info, cmd: string,
			arg: string): string
	{
	local site_cmd_arg = split1(arg, /[ \t]*/);

	local site_cmd = site_cmd_arg[1];
	local site_cmd_upper = to_upper(site_cmd);

	if ( site_cmd_upper in ftp_known_site_cmd )
		{
		if ( length(site_cmd_arg) > 1 )
			{
			# If the there is an argument after "SITE <cmd>"
			local site_arg = site_cmd_arg[2];
			site_arg =
				anonymize_arg(fmt("arg_of_site_%s", site_cmd),
						session, cmd, site_arg, cmd);
			return string_cat(site_cmd, " ", site_arg);
			}
		else
			{
			return leave_in_the_clear("known_site_command", session,
						site_cmd,
						fmt("%s %s", cmd, arg));
			}
		}
	else
		return anonymize_arg("site_arg", session, cmd, arg, cmd);
	}

function anonymize_port_arg(session: ftp_session_info, cmd: string,
				arg: string): string
	{
	local data = parse_ftp_port(arg);

	if ( data$valid )
		{
		local a: addr;
		# Anonymize the address part
		a = anonymize_address(data$h, session$connection_id);
		return fmt_ftp_port(a, data$p);
		}
	else
		return anonymize_arg("unrecognized_ftp_port", session, cmd, arg, "");
	}

# EPRT is an extension to the PORT command
function anonymize_eprt_arg(session: ftp_session_info, cmd: string,
				arg: string): string
	{
	if ( arg != ftp_eprt_pat )
		return anonymize_arg("unrecognized_EPRT_arg", session, cmd, arg, "");

	local parts = split(arg, /\|/);
	# Anonymize the address part
	local a = parse_dotted_addr(parts[3]);
	a = anonymize_address(a, session$connection_id);
	return fmt("|%s|%s|%s|", parts[2], a, parts[4]);
	}

# Anonymize arguments of commands that we do not understand
function anonymize_other_arg(session: ftp_session_info, cmd: string, arg: string): string
	{
	local anon: string;

	# Try to guess what the arg is

	local data = parse_ftp_port(arg);
	if ( arg == ftp_port_pat && data$valid )
		# Here we do not check whether data$h == session$connection_id$orig_h
		# because sometimes it's not the case, but we will try to anonymize it anyway.
		{
		anon = anonymize_port_arg(session, cmd, arg);
		print ftp_anon_log, fmt("anonymize_arg: (%s) {} %s \"%s\" to \"%s\" in [%s]",
					"port arg of non-port command",
					cmd, arg, anon, id_string(session$connection_id));
		}

	else if ( arg == ftp_ip_pat )
		{
		local a = parse_dotted_addr(arg);
		a = anonymize_address(a, session$connection_id);
		anon = cat(a);
		}

	else if ( arg == ftp_domain_name_pat )
		{
		anon = "<domain name>";
		}

	else if ( arg == "." )
		{
		anon = arg;
		leave_in_the_clear(".", session, arg, fmt("%s %s", cmd, arg));
		}

	else
		# Anonymize by default.
		anon = anonymize_arg("cannot_understand_arg",
					session, cmd, arg, cmd);

	return anon;
	}

# Anonymize the command and argument, and put the results in
# cmd_arg$anonymized_{cmd, arg}
function anonymize_ftp_cmd_arg(session: ftp_session_info,
				cmd_arg: ftp_cmd_arg)
	{
	local cmd = cmd_arg$cmd;
	local arg = cmd_arg$arg;
	local anon : string;

	cmd_arg$anonymized_cmd = cmd;

	local ret: ftp_cmd_arg_anon_result;

	if ( trace_specific_cmd_arg_anonymization )
		ret = anonymize_trace_specific_cmd_arg(session, cmd, arg);
	else
		ret$anonymized = F;

	if ( ret$anonymized )
		{
		# If the trace-specific anonymization applies to the cmd_arg
			print ftp_anon_log, fmt("anonymize_arg: (%s) \"%s %s\" to \"%s %s\" in [%s]",
				"trace-specific",
				cmd, to_string_literal(arg),
				ret$cmd, to_string_literal(ret$arg),
				id_string(session$connection_id));
		cmd_arg$anonymized_cmd = ret$cmd;
		anon = ret$arg;
		}

	else if ( [cmd, arg] in ftp_special_cmd_args )
		{
		anon = ftp_special_cmd_args[cmd, arg];
		print ftp_anon_log, fmt("anonymize_arg: (%s) [%s] \"%s\" to \"%s\" in [%s]",
					"special_arg_transformation",
					cmd,
					to_string_literal(arg),
					to_string_literal(anon),
					id_string(session$connection_id));
		}

	else if ( to_upper(string_cat(cmd, " ", arg)) == ftp_safe_cmd_arg_pattern ||
		  [cmd, arg] in ftp_safe_arg_list )
		{
		leave_in_the_clear("safe_arg", session, arg, fmt("%s %s", cmd, arg));
		anon = arg;
		}

	else if ( cmd == "USER" || cmd == "ACCT" )
		anon = (arg in ftp_guest_ids) ?
			arg : anonymize_user_id(session, arg, LOGIN_PENDING, "");

	else if ( cmd == "PASS" )
		anon = "<password>";

	else if ( cmd in ftp_cmds_with_no_arg )
		anon = (arg == "") ?
			"" :
			anonymize_arg("should_have_been_empty",
					session, cmd, arg, cmd);

	else if ( cmd in ftp_cmds_with_file_arg )
		{
		if ( session$user in ftp_guest_ids )
			anon = ( arg == "" ) ? "" : anonymize_file_name_arg(session, cmd, arg, F);
		else
			anon = "<path>";
		}

	else if ( cmd in ftp_cmds_with_safe_arg )
		anon = check_safe_arg(session, cmd, arg);

	else if ( cmd == "SITE" )
		anon = check_site_arg(session, cmd, arg);

	else if ( cmd == "PORT" )
		anon = anonymize_port_arg(session, cmd, arg);

	else if ( cmd == "EPRT" )
		anon = anonymize_eprt_arg(session, cmd, arg);

	else if ( cmd == "AUTH" )
		anon = anonymize_arg("rejected_auth_arg", session, cmd, arg, cmd);

	else
		{
		if ( cmd == /<.*>/ )
			cmd_arg$anonymized_cmd = "";

		else if ( cmd !in ftp_other_cmds )
			{
			local a = anonymize_string(string_cat("cmd:", cmd));
			print ftp_anon_log, fmt("anonymize_cmd: (%s) \"%s\" [%s] to \"%s\" in [%s]",
				"unrecognized command", to_string_literal(cmd),
				to_string_literal(arg), a,
				id_string(session$connection_id));
			cmd_arg$anonymized_cmd = a;
			}

		anon = anonymize_other_arg(session, cmd, arg);
		}

	if ( cmd == "USER" )
		session$anonymized_user = anon;

	cmd_arg$anonymized_arg = anon;
	}


# We delay anonymization of certain requests till we see the reply:
# when the argument of a USER command is a sensitive user ID, we
# anonymize the ID if the login is successful and leave the ID in the
# clear otherwise.
#
# The function returns T if the decision should be delayed.

function delay_rewriting_request(session: ftp_session_info, cmd: string,
				 arg: string): bool
	{
	return (cmd == "USER" && arg !in ftp_guest_ids) ||
		(cmd == "AUTH") ||
		(cmd in ftp_cmds_with_file_arg &&
		 session$connection_id$resp_h in ftp_public_servers);
	}

function ftp_request_rewrite(c: connection, session: ftp_session_info,
				cmd_arg: ftp_cmd_arg): bool
	{
	local cmd = cmd_arg$cmd;
	local arg = cmd_arg$arg;

	if ( delay_rewriting_request(session, cmd, arg) )
		{
		cmd_arg$rewrite_slot = reserve_rewrite_slot(c);
		session$delayed_request_rewrite[cmd_arg$seq] = cmd_arg;
		return F;
		}
	else
		{
		anonymize_ftp_cmd_arg(session, cmd_arg);
		rewrite_ftp_request(c, cmd_arg$anonymized_cmd,
					cmd_arg$anonymized_arg);
		return T;
		}
	}

function do_rewrite_delayed_ftp_request(c: connection, delayed: ftp_cmd_arg)
	{
	seek_rewrite_slot(c, delayed$rewrite_slot);

	rewrite_ftp_request(c, delayed$cmd == /<.*>/ ? "" : delayed$cmd,
				delayed$anonymized_arg);
	release_rewrite_slot(c, delayed$rewrite_slot);

	delayed$rewrite_slot = 0;
	}

function delayed_ftp_request_rewrite(c: connection, session: ftp_session_info,
					delayed: ftp_cmd_arg,
					current: ftp_cmd_arg,
					reply_code: count)
	{
	local cmd = delayed$cmd;
	local arg = delayed$arg;

	if ( cmd == "USER" )
		{
		delayed$anonymized_cmd = cmd;

		local login_status: login_status_type;

		if ( reply_code == 0 )
			login_status = LOGIN_UNKNOWN;

		else if ( delayed$seq == current$seq ||
		     current$cmd == "PASS" ||
		     current$cmd == "ACCT" )
				{
			if ( reply_code >= 330 && reply_code < 340 ) # need PASS/ACCT
				login_status = LOGIN_PENDING; # wait to see outcome of PASS

			else if ( reply_code >= 400 && reply_code < 600 )
					login_status = LOGIN_FAILED;

			else if ( reply_code >= 230 && reply_code < 240 )
				login_status = LOGIN_SUCCESSFUL;

			else
				login_status = LOGIN_UNKNOWN;
			}

		else if ( current$cmd == "USER" ) # another login attempt
			login_status = LOGIN_FAILED;

		else if ( reply_code == 230 )
			login_status = LOGIN_SUCCESSFUL;

		else if ( reply_code == 530 )
			login_status = LOGIN_FAILED;

		else
			login_status = LOGIN_UNKNOWN;

		if ( login_status != LOGIN_PENDING )
			{
			delayed$anonymized_arg =
				anonymize_user_id(session, arg, login_status,
					fmt("(%s %s) %s %s -> %d", cmd, arg, current$cmd, current$arg, reply_code));
			do_rewrite_delayed_ftp_request(c, delayed);
			}
		}

	else if ( cmd == "AUTH" )
		{
		delayed$anonymized_cmd = cmd;

		if ( reply_code >= 500 && reply_code < 600 )
			# if AUTH fails
			{
			anonymize_ftp_cmd_arg(session, delayed);
			do_rewrite_delayed_ftp_request(c, delayed);
			}

		else if ( reply_code >= 300 && reply_code < 400 )
			;
		else 	# otherwise always anonymize the argument
			{
			delayed$anonymized_arg = "<auth_mechanism>";
			do_rewrite_delayed_ftp_request(c, delayed);
			}
		}

	else if ( cmd in ftp_cmds_with_file_arg && session$connection_id$resp_h in ftp_public_servers )
		{
		delayed$anonymized_cmd = cmd;

		# The argument represents a valid file name on a
		# public server only if the operation is successful.
		delayed$anonymized_arg =
			anonymize_file_name_arg(session, cmd, arg,
				(cmd != "LIST" && cmd != "NLST" &&
				 reply_code >= 100 && reply_code < 300));
		do_rewrite_delayed_ftp_request(c, delayed);
		}

	else
		{
		print ftp_anon_log, "ERROR! unrecognizable delayed ftp request rewrite";

		anonymize_ftp_cmd_arg(session, delayed);
		do_rewrite_delayed_ftp_request(c, delayed);
		}
	}

function process_delayed_rewrites(c: connection, session: ftp_session_info, reply_code: count, cmd_arg: ftp_cmd_arg)
	{
	local written: table[count] of ftp_cmd_arg;

	for ( s in session$delayed_request_rewrite )
		{
		local ca = session$delayed_request_rewrite[s];
		delayed_ftp_request_rewrite(c, session, ca, cmd_arg,
					reply_code);

		if ( ca$rewrite_slot == 0 )
			written[ca$seq] = ca;
		}

	for ( s in written )
		delete session$delayed_request_rewrite[s];
	}

function ftp_reply_rewrite(c: connection, session: ftp_session_info,
				code: count, msg: string, cont_resp: bool,
				cmd_arg: ftp_cmd_arg)
	{
	local actual_code = session$reply_code;
	local xyz = parse_ftp_reply_code(actual_code);

	process_delayed_rewrites(c, session, actual_code, cmd_arg);

	if ( process_ftp_reply_by_message_pattern )
		{
		# See *ftp-reply-pattern.bro* for reply anonymization
		local anon_msg = anonymize_ftp_reply_by_msg_pattern(actual_code, msg,
					cmd_arg, session);
		rewrite_ftp_reply(c, code, anon_msg, cont_resp);
		}
	else
		rewrite_ftp_reply(c, code, "<ftp reply message stripped out>", cont_resp);
	}


const eliminate_scans = F &redef;
const port_scanners: set[addr] &redef;
global eliminate_scan_for_host: table[addr] of bool;

function eliminate_scan(id: conn_id): bool
	{
	local h = id$resp_h;

	if ( h !in eliminate_scan_for_host )
		{
		# if the hash string starts with [0-7], i.e. with probability of 50%
		eliminate_scan_for_host[h] = (/^[0-7]/ in md5_hmac(h));
		if ( eliminate_scan_for_host[h] )
			print ftp_anon_log, fmt("eliminate_scans_for_host %s", h);
		}

	return eliminate_scan_for_host[h];
	}

redef call_ftp_connection_remove = T;

function ftp_connection_remove(c: connection)
	{
	if ( c$id in ftp_sessions )
		{
		local session = ftp_sessions[c$id];
		process_delayed_rewrites(c, session, 0, find_ftp_pending_cmd(session$pending_requests, 0, ""));
		}

	if ( eliminate_scans && ! requires_trace_commitment )
		print ftp_anon_log,
			fmt("ERROR: requires_trace_commitment must be set to true in order to allow scan elimination");

	if ( requires_trace_commitment )
		{
		local id = c$id;
		local eliminate = F;

		if ( eliminate_scans &&
		     # To check if the connection is part of a port scan
		     (id !in ftp_sessions ||
		      ftp_sessions[id]$num_requests == 0 ||
		      id$orig_h in port_scanners) &&
		     eliminate_scan(id) )
			rewrite_commit_trace(c, F, T);
		else
			rewrite_commit_trace(c, T, T);
		}
	}
