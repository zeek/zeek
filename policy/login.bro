# $Id: login.bro 6481 2008-12-15 00:47:57Z vern $

@load notice
@load weird
@load hot-ids
@load conn
# scan.bro is needed for "account_tried" event.
@load scan
@load demux
@load terminate-connection

module Login;

global telnet_ports = { 23/tcp } &redef;
redef dpd_config += { [ANALYZER_TELNET] = [$ports = telnet_ports] };

global rlogin_ports = { 513/tcp } &redef;
redef dpd_config += { [ANALYZER_RLOGIN] = [$ports = rlogin_ports] };

export {
	redef enum Notice += {
		SensitiveLogin,		# interactive login using sensitive username

		# Interactive login seen using forbidden username, but the analyzer
		# was confused in following the login dialog, so may be in error.
		LoginForbiddenButConfused,

		# During a login dialog, a sensitive username (e.g., "rewt") was
		# seen in the user's *password*.  This is reported as a notice
		# because it could be that the login analyzer didn't track the
		# authentication dialog correctly, and in fact what it thinks is
		# the user's password is instead the user's username.
		SensitiveUsernameInPassword,
	};

	# If these patterns appear anywhere in the user's keystrokes, do a notice.
	const input_trouble =
		  /rewt/
		| /eggdrop/
		| /\/bin\/eject/
		| /oir##t/
		| /ereeto/
		| /(shell|xploit)_?code/
		| /execshell/
		| /ff\.core/
		| /unset[ \t]+(histfile|history|HISTFILE|HISTORY)/
		| /neet\.tar/
		| /r0kk0/
		| /su[ \t]+(daemon|news|adm)/
		| /\.\/clean/
		| /rm[ \t]+-rf[ \t]+secure/
		| /cd[ \t]+\/dev\/[a-zA-Z]{3}/
		| /solsparc_lpset/
		| /\.\/[a-z]+[ \t]+passwd/
		| /\.\/bnc/
		| /bnc\.conf/
		| /\"\/bin\/ksh\"/
		| /LAST STAGE OF DELIRIUM/
		| /SNMPXDMID_PROG/
		| /snmpXdmid for solaris/
		| /\"\/bin\/uname/
		| /gcc[ \t]+1\.c/
		| />\/etc\/passwd/
		| /lynx[ \t]+-source[ \t]+.*(packetstorm|shellcode|linux|sparc)/
		| /gcc.*\/bin\/login/
		| /#define NOP.*0x/
		| /printf\(\"overflowing/
		| /exec[a-z]*\(\"\/usr\/openwin/
		| /perl[ \t]+.*x.*[0-9][0-9][0-9][0-9]/
		| /ping.*-s.*%d/
	&redef;

	# If this pattern appears anywhere in the user's input after applying
	# <backspace>/<delete> editing, do a notice ...
	const edited_input_trouble =
		/[ \t]*(cd|pushd|more|less|cat|vi|emacs|pine)[ \t]+((['"]?\.\.\.)|(["'](\.*)[ \t]))/
	&redef;

	# ... *unless* the corresponding output matches this:
	const output_indicates_input_not_trouble = /No such file or directory/ &redef;

	# NOTICE on these, but only after waiting for the corresponding output,
	# so it can be displayed at the same time.
	const input_wait_for_output = edited_input_trouble &redef;

	# If the user's entire input matches this pattern, do a notice.  Putting
	# "loadmodule" here rather than in input_trouble is just to illustrate
	# the idea, it could go in either.
	const full_input_trouble = /.*loadmodule.*/ &redef;

	# If the following appears anywhere in the user's output, do a notice.
	const output_trouble =
		  /^-r.s.*root.*\/bin\/(sh|csh|tcsh)/
		| /Jumping to address/
		| /Jumping Address/
		| /smashdu\.c/
		| /PATH_UTMP/
		| /Log started at =/
		| /www\.anticode\.com/
		| /www\.uberhax0r\.net/
		| /smurf\.c by TFreak/
		| /Super Linux Xploit/
		| /^# \[root@/
		| /^-r.s.*root.*\/bin\/(time|sh|csh|tcsh|bash|ksh)/
		| /invisibleX/
		| /PATH_(UTMP|WTMP|LASTLOG)/
		| /[0-9]{5,} bytes from/
		| /(PATH|STAT):\ .*=>/
		| /----- \[(FIN|RST|DATA LIMIT|Timed Out)\]/
		| /IDLE TIMEOUT/
		| /DATA LIMIT/
		| /-- TCP\/IP LOG --/
		| /STAT: (FIN|TIMED_OUT) /
		| /(shell|xploit)_code/
		| /execshell/
		| /x86_bsd_compaexec/
		| /\\xbf\\xee\\xee\\xee\\x08\\xb8/	# from x.c worm
		| /Coded by James Seter/
		| /Irc Proxy v/
		| /Daemon port\.\.\.\./
		| /BOT_VERSION/
		| /NICKCRYPT/
		| /\/etc\/\.core/
		| /exec.*\/bin\/newgrp/
		| /deadcafe/
		| /[ \/]snap\.sh/
		| /Secure atime,ctime,mtime/
		| /Can\'t fix checksum/
		| /Promisc Dectection/
		| /ADMsn0ofID/
		| /(cd \/; uname -a; pwd; id)/
		| /drw0rm/
		| /[Rr][Ee3][Ww][Tt][Ee3][Dd]/
		| /rpc\.sadmin/
		| /AbraxaS/
		| /\[target\]/
		| /ID_SENDSYN/
		| /ID_DISTROIT/
		| /by Mixter/
		| /rap(e?)ing.*using weapons/
		| /spsiod/
		| /[aA][dD][oO][rR][eE][bB][sS][dD]/	# rootkit
	&redef;

	# Same, but must match entire output.
	const full_output_trouble = /.*Trojaning in progress.*/ &redef;

	const backdoor_prompts =
		  /^[!-~]*( ?)[#%$] /
		| /.*no job control/
		| /WinGate>/
	&redef;

	const non_backdoor_prompts = /^ *#.*#/ &redef;
	const hot_terminal_types = /VT666|007/ &redef;
	const hot_telnet_orig_ports = { 53982/tcp, } &redef;
	const router_prompts: set[string] &redef;
	const non_ASCII_hosts: set[addr] &redef;
	const skip_logins_to = { non_ASCII_hosts, } &redef;
	const always_hot_login_ids = { always_hot_ids } &redef;
	const hot_login_ids = { hot_ids } &redef;
	const rlogin_id_okay_if_no_password_exposed = { "root", } &redef;

	const BS = "\x08";
	const DEL = "\x7f";

	global new_login_session:
		function(c: connection, pid: peer_id, output_line: count);
	global remove_login_session: function(c: connection, pid: peer_id);
	global ext_set_login_state:
		function(cid: conn_id, pid: peer_id, state: count);
	global ext_get_login_state:
		function(cid: conn_id, pid: peer_id): count;
}

redef capture_filters += { ["login"] = "port telnet or tcp port 513" };

redef skip_authentication = {
	"WELCOME TO THE BERKELEY PUBLIC LIBRARY",
};

redef direct_login_prompts = { "TERMINAL?", };

redef login_prompts = {
	"Login:", "login:", "Name:", "Username:", "User:", "Member Name",
	"User Access Verification", "Cisco Systems Console",
	direct_login_prompts
};

redef login_non_failure_msgs = {
	"Failures", "failures",	# probably is "<n> failures since last login"
	"failure since last successful login",
	"failures since last successful login",
};

redef login_non_failure_msgs = {
	"Failures", "failures",	# probably is "<n> failures since last login"
	"failure since last successful login",
	"failures since last successful login",
} &redef;

redef login_failure_msgs = {
	"invalid", "Invalid", "incorrect", "Incorrect", "failure", "Failure",
	# "Unable to authenticate", "unable to authenticate",
	"User authorization failure",
	"Login failed",
	"INVALID", "Sorry.", "Sorry,",
};

redef login_success_msgs = {
	"Last login",
	"Last successful login", "Last   successful login",
	"checking for disk quotas", "unsuccessful login attempts",
	"failure since last successful login",
	"failures since last successful login",
	router_prompts,
};

redef login_timeouts = {
	"timeout", "timed out", "Timeout", "Timed out",
	"Error reading command input",	# VMS
};


type check_info: record {
	expanded_line: string;	# line with all possible editing seqs
	hot: bool;	# whether any editing sequence was a hot user id
	hot_id: string;	# the ID considered hot
	forbidden: bool;	# same, but forbidden user id
};

type login_session_info: record {
	user: string;
	output_line: count;	# number of lines seen

	# input string for which we want to match the output.
	waiting_for_output: string;
	waiting_for_output_line: count;	# output line we want to match it to
	state: count;	# valid for external connections only
};

global login_sessions: table[peer_id, conn_id] of login_session_info;


# The next two functions are "external-to-the-event-engine",
# hence the ext_ prefix.  They're used by the script to manage
# login state so that they can work with login sessions unknown
# to the event engine (such as those received from remote peers).

function ext_get_login_state(cid: conn_id, pid: peer_id): count
	{
	if ( pid == PEER_ID_NONE )
		return get_login_state(cid);

	return login_sessions[pid, cid]$state;
	}

function ext_set_login_state(cid: conn_id, pid: peer_id, state: count)
	{
	if ( pid == PEER_ID_NONE )
		set_login_state(cid, state);
	else
		login_sessions[pid, cid]$state = state;
	}

function new_login_session(c: connection, pid: peer_id, output_line: count)
	{
	local s: login_session_info;
	s$waiting_for_output = s$user = "";
	s$output_line = output_line;
	s$state = LOGIN_STATE_AUTHENTICATE;

	login_sessions[pid, c$id] = s;
	}

function remove_login_session(c: connection, pid: peer_id)
	{
	delete login_sessions[pid, c$id];
	}

function is_login_conn(c: connection): bool
	{
	return c$id$resp_p == telnet || c$id$resp_p == rlogin;
	}

function hot_login(c: connection, pid: peer_id, msg: string, tag: string)
	{
	if ( [pid, c$id] in login_sessions )
		NOTICE([$note=SensitiveLogin, $conn=c,
			$user=login_sessions[pid, c$id]$user, $msg=msg]);
	else
		NOTICE([$note=SensitiveLogin, $conn=c, $msg=msg]);

	++c$hot;
	demux_conn(c$id, tag, "keys", service_name(c));
	}

function is_hot_id(id: string, successful: bool, confused: bool): bool
	{
	return successful ? id in hot_login_ids :
		(confused ? id in forbidden_ids :
			id in always_hot_login_ids);
	}

function is_forbidden_id(id: string): bool
	{
	return id in forbidden_ids || id == forbidden_id_patterns;
	}

function edit_and_check_line(c: connection, pid: peer_id, line: string,
				successful: bool): check_info
	{
	line = to_lower(line);

	local ctrl_H_edit = edit(line, BS);
	local del_edit = edit(line, DEL);

	local confused =
		(ext_get_login_state(c$id, pid) == LOGIN_STATE_CONFUSED);
	local hot = is_hot_id(line, successful, confused);
	local hot_id = hot ? line : "";
	local forbidden = is_forbidden_id(line);

	local eline = line;

	if ( ctrl_H_edit != line )
		{
		eline = fmt("%s,%s", eline, ctrl_H_edit);
		if ( ! hot && is_hot_id(ctrl_H_edit, successful, confused) )
			{
			hot = T;
			hot_id = ctrl_H_edit;
			}

		forbidden = forbidden || is_forbidden_id(ctrl_H_edit);
		}

	if ( del_edit != line )
		{
		eline = fmt("%s,%s", eline, del_edit);
		if ( ! hot && is_hot_id(del_edit, successful, confused) )
			{
			hot = T;
			hot_id = del_edit;
			}

		forbidden = forbidden || is_forbidden_id(del_edit);
		}

	local results: check_info;
	results$expanded_line = eline;
	results$hot = hot;
	results$hot_id = hot_id;
	results$forbidden = forbidden;

	return results;
	}

function edit_and_check_user(c: connection, pid: peer_id, user: string,
				successful: bool, fmt_s: string): bool
	{
	local check = edit_and_check_line(c, pid, user, successful);

	if ( [pid, c$id] !in login_sessions )
		new_login_session(c, pid, 9999);

	login_sessions[pid, c$id]$user = check$expanded_line;

	c$addl = fmt(fmt_s, c$addl, check$expanded_line);

	if ( check$hot )
		{
		++c$hot;
		demux_conn(c$id, check$hot_id, "keys", service_name(c));
		}

	if ( check$forbidden )
		{
		if ( ext_get_login_state(c$id, pid) == LOGIN_STATE_CONFUSED )
			NOTICE([$note=LoginForbiddenButConfused, $conn=c,
				$user = user,
				$msg=fmt("not terminating %s because confused about state", full_id_string(c))]);
		else
			TerminateConnection::terminate_connection(c);
		}

	return c$hot > 0;
	}

function edit_and_check_password(c: connection, pid: peer_id, password: string)
	{
	local check = edit_and_check_line(c, pid, password, T);
	if ( check$hot )
		{
		++c$hot;
		NOTICE([$note=SensitiveUsernameInPassword, $conn=c,
			$user=password,
			$msg=fmt("%s password: \"%s\"",
				id_string(c$id), check$expanded_line)]);
		}
	}

event login_failure(c: connection, user: string, client_user: string,
			password: string, line: string)
	{
	local pid = get_event_peer()$id;

	event account_tried(c, user, password);
	edit_and_check_password(c, pid, password);

	if ( c$hot == 0 && password == "" &&
	     ! edit_and_check_line(c, pid, user, F)$hot )
		# Don't both reporting it, this was clearly a half-hearted
		# attempt and it's not a sensitive username.
		return;

	local user_hot = edit_and_check_user(c, pid, user, F, "%sfail/%s ");
	if ( client_user != "" && client_user != user &&
	     edit_and_check_user(c, pid, client_user, F, "%s(%s) ") )
		user_hot = T;

	if ( user_hot || c$hot > 0 )
		NOTICE([$note=SensitiveLogin, $conn=c,
			$user=user, $sub=client_user,
			$msg=fmt("%s %s", id_string(c$id), c$addl)]);
	}

event login_success(c: connection, user: string, client_user: string,
			password: string, line: string)
	{
	local pid = get_event_peer()$id;

	Hot::check_hot(c, Hot::APPL_ESTABLISHED);
	event account_tried(c, user, password);
	edit_and_check_password(c, pid, password);

	# Look for whether the user name is sensitive; but allow for
	# some ids being okay if no password was exposed accessing them.
	local user_hot = F;
	if ( c$id$resp_p == rlogin && password == "<none>" &&
	     user in rlogin_id_okay_if_no_password_exposed )
		append_addl(c, fmt("\"%s\"", user));

	else
		user_hot = edit_and_check_user(c, pid, user, T, "%s\"%s\" ");

	if ( c$id$resp_p == rlogin && client_user in always_hot_login_ids )
		{
		append_addl(c, fmt("(%s)", client_user));
		demux_conn(c$id, client_user, "keys", service_name(c));
		user_hot = T;
		}

	if ( user_hot || c$hot > 0 )
		NOTICE([$note=SensitiveLogin, $conn=c,
			$user=user, $sub=client_user,
			$msg=fmt("%s %s", id_string(c$id), c$addl)]);

	# else if ( password == "" )
	# 	alarm fmt("%s %s <no password>", id_string(c$id), c$addl);

### use the following if no login_input_line/login_output_line
# 	else
# 		{
# 		set_record_packets(c$id, F);
# 		skip_further_processing(c$id);
# 		}
	}

event login_input_line(c: connection, line: string)
	{
	local pid = get_event_peer()$id;
	local BS_line = edit(line, BS);
	local DEL_line = edit(line, DEL);
	if ( input_trouble in line ||
	### need to merge input_trouble and edited_input_trouble here
	### ideally, match on input_trouble would tell whether we need
	### to invoke the edit functions, as an attribute of a .*(^H|DEL)
	### rule.
	     input_trouble in BS_line || input_trouble in DEL_line ||
	     (edited_input_trouble in BS_line &&
	      # If one is in but the other not, then the one that's not
	      # is presumably the correct edit, and the one that is, isn't
	      # in fact edited at all
	      edited_input_trouble in DEL_line) ||
	     line == full_input_trouble )
		{
		if ( [pid, c$id] !in login_sessions )
			new_login_session(c, pid, 9999);

		if ( edited_input_trouble in BS_line &&
		     edited_input_trouble in DEL_line )
			{
			login_sessions[pid, c$id]$waiting_for_output = line;
			login_sessions[pid, c$id]$waiting_for_output_line =
				# We don't want the *next* line, that's just
				# the echo of this input.
				login_sessions[pid, c$id]$output_line + 2;
			}

		else if ( ++c$hot <= 2 )
			hot_login(c, pid, fmt("%s input \"%s\"", id_string(c$id), line), "trb");
		}
	}

event login_output_line(c: connection, line: string)
	{
	local pid = get_event_peer()$id;
	if ( [pid, c$id] !in login_sessions )
		new_login_session(c, pid, 9999);

	local s = login_sessions[pid, c$id];

	if ( line != "" && ++s$output_line == 1 )
		{
		if ( byte_len(line) < 40 &&
		     backdoor_prompts in line && non_backdoor_prompts !in line )
			hot_login(c, pid, fmt("%s possible backdoor \"%s\"", id_string(c$id), line), "trb");
		}

	if ( s$waiting_for_output != "" &&
	     s$output_line >= s$waiting_for_output_line )
		{
		if ( output_indicates_input_not_trouble !in line )
			hot_login(c, pid,
				fmt("%s input \"%s\" yielded output \"%s\"",
					id_string(c$id),
					s$waiting_for_output,
					line),
				"trb");

		s$waiting_for_output = "";
		}

	if ( byte_len(line) < 256 &&
	     (output_trouble in line || line == full_output_trouble) &&
	     ++c$hot <= 2 )
		hot_login(c, pid, fmt("%s output \"%s\"", id_string(c$id), line), "trb");
	}

event login_confused(c: connection, msg: string, line: string)
	{
	Hot::check_hot(c, Hot::APPL_ESTABLISHED);

	append_addl(c, "<confused>");

	if ( line == "" )
		print Weird::weird_file, fmt("%.6f %s %s", network_time(), id_string(c$id), msg);
	else
		print Weird::weird_file, fmt("%.6f %s %s (%s)", network_time(), id_string(c$id), msg, line);

	set_record_packets(c$id, T);
	}

event login_confused_text(c: connection, line: string)
	{
	local pid = get_event_peer()$id;
	if ( c$hot == 0 && edit_and_check_line(c, pid, line, F)$hot )
		{
		local ignore =
			edit_and_check_user(c, pid, line, F, "%sconfused/%s ");
		NOTICE([$note=SensitiveLogin, $conn=c,
			$user=line,
			$msg=fmt("%s %s", id_string(c$id), c$addl)]);
		set_record_packets(c$id, T);
		}
	}

event login_terminal(c: connection, terminal: string)
	{
	local pid = get_event_peer()$id;
	if ( hot_terminal_types in terminal )
		hot_login(c, pid,
			fmt("%s term %s", id_string(c$id), terminal), "trb");
	}

event login_prompt(c: connection, prompt: string)
	{
	# Could check length >= 6, per Solaris exploit ...
	local pid = get_event_peer()$id;
	hot_login(c, pid,
		fmt("%s $TTYPROMPT %s", id_string(c$id), prompt), "trb");
	}

event excessive_line(c: connection)
	{
	if ( is_login_conn(c) )
		{
		local pid = get_event_peer()$id;

		if ( ! c$hot && c$id$resp_h in non_ASCII_hosts )
			{
			ext_set_login_state(c$id, pid, LOGIN_STATE_SKIP);
			set_record_packets(c$id, F);
			}
		else if ( ext_get_login_state(c$id, pid) == LOGIN_STATE_AUTHENTICATE )
			{
			event login_confused(c, "excessive_line", "");
			ext_set_login_state(c$id, pid, LOGIN_STATE_CONFUSED);
			}
		}
	}

event inconsistent_option(c: connection)
	{
	print Weird::weird_file, fmt("%.6f %s inconsistent option", network_time(), id_string(c$id));
	}

event bad_option(c: connection)
	{
	print Weird::weird_file, fmt("%.6f %s bad option", network_time(), id_string(c$id));
	}

event bad_option_termination(c: connection)
	{
	print Weird::weird_file, fmt("%.6f %s bad option termination", network_time(), id_string(c$id));
	}

event authentication_accepted(name: string, c: connection)
	{
	local addl_msg = fmt("auth/%s", name);
	append_addl(c, addl_msg);
	}

event authentication_rejected(name: string, c: connection)
	{
	append_addl(c, fmt("auth-failed/%s", name));
	}

event authentication_skipped(c: connection)
	{
	append_addl(c, "(skipped)");
	skip_further_processing(c$id);

	if ( ! c$hot )
		set_record_packets(c$id, F);
	}

event connection_established(c: connection)
	{
	if ( is_login_conn(c) )
		{
		local pid = get_event_peer()$id;

		new_login_session(c, pid, 0);

		if ( c$id$resp_h in skip_logins_to )
			event authentication_skipped(c);

		if ( c$id$resp_p == telnet &&
		     c$id$orig_p in hot_telnet_orig_ports )
			hot_login(c, pid, fmt("%s hot_orig_port", id_string(c$id)), "orig");
		}
	}

event partial_connection(c: connection)
	{
	if ( is_login_conn(c) )
		{
		local pid = get_event_peer()$id;
		new_login_session(c, pid, 9999);
		ext_set_login_state(c$id, pid, LOGIN_STATE_CONFUSED);

		if ( c$id$resp_p == telnet &&
		     c$id$orig_p in hot_telnet_orig_ports )
			hot_login(c, pid, fmt("%s hot_orig_port", id_string(c$id)), "orig");
		}
	}

event connection_finished(c: connection)
	{
	local pid = get_event_peer()$id;
	remove_login_session(c, pid);
	}

event activating_encryption(c: connection)
	{
	if ( is_login_conn(c) )
		append_addl(c, "(encrypted)");
	}
