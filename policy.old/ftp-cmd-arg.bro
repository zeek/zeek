# $Id: ftp-cmd-arg.bro 416 2004-09-17 03:52:28Z vern $

# For debugging purpose only
# global ftp_cmd_reply_log = open_log_file("ftp-cmd-arg") &redef;

const ftp_cmd_reply_code: set[string, count] = {
	# According to RFC 959
	["<init>", [120, 220, 421]],
	["USER", [230, 530, 500, 501, 421, 331, 332]],
	["PASS", [230, 202, 530, 500, 501, 503, 421, 332]],
	["ACCT", [230, 202, 530, 500, 501, 503, 421]],
	["CWD", [250, 500, 501, 502, 421, 530, 550]],
	["CDUP", [200, 500, 501, 502, 421, 530, 550]],
	["SMNT", [202, 250, 500, 501, 502, 421, 530, 550]],
	["REIN", [120, 220, 421, 500, 502]],
	["QUIT", [221, 500]],
	["PORT", [200, 500, 501, 421, 530]],
	["PASV", [227, 500, 501, 502, 421, 530]],
	["MODE", [200, 500, 501, 504, 421, 530]],
	["TYPE", [200, 500, 501, 504, 421, 530]],
	["STRU", [200, 500, 501, 504, 421, 530]],
	["ALLO", [200, 202, 500, 501, 504, 421, 530]],
	["REST", [500, 501, 502, 421, 530, 350]],
	["STOR", [125, 150, 110, 226, 250, 425, 426, 451, 551, 552, 532, 450, 452, 553, 500, 501, 421, 530]],
	["STOU", [125, 150, 110, 226, 250, 425, 426, 451, 551, 552, 532, 450, 452, 553, 500, 501, 421, 530]],
	["RETR", [125, 150, 110, 226, 250, 425, 426, 451, 450, 550, 500, 501, 421, 530]],
	["LIST", [125, 150, 226, 250, 425, 426, 451, 450, 500, 501, 502, 421, 530]],
	["NLST", [125, 150, 226, 250, 425, 426, 451, 450, 500, 501, 502, 421, 530]],
	["APPE", [125, 150, 226, 250, 425, 426, 451, 551, 552, 532, 450, 550, 452, 553, 500, 501, 502, 421, 530]],
	["RNFR", [450, 550, 500, 501, 502, 421, 530, 350]],
	["RNTO", [250, 532, 553, 500, 501, 502, 503, 421, 530]],
	["DELE", [250, 450, 550, 500, 501, 502, 421, 530]],
	["RMD", [250, 500, 501, 502, 421, 530, 550]],
	["MKD", [257, 500, 501, 502, 421, 530, 550]],
	["PWD", [257, 500, 501, 502, 421, 550]],
	["ABOR", [225, 226, 500, 501, 502, 421]],
	["SYST", [215, 500, 501, 502, 421]],
	["STAT", [211, 212, 213, 450, 500, 501, 502, 421, 530]],
	["HELP", [211, 214, 500, 501, 502, 421]],
	["SITE", [200, 202, 500, 501, 530]],
	["NOOP", [200, 500, 421]],

	# Extensions

#	["SIZE", [213, 550]],
#	["SITE", 214],
#	["MDTM", 213],
#	["EPSV", 500],
#	["FEAT", 500],
#	["OPTS", 500],

#	["CDUP", 250],
#	["CLNT", 200],
#	["CLNT", 500],
#	["EPRT", 500],

#	["FEAT", 211],
#	["HELP", 200],
#	["LIST", 550],
#	["LPRT", 500],
#	["MACB", 500],
#	["MDTM", 212],
#	["MDTM", 500],
#	["MDTM", 501],
#	["MDTM", 550],
#	["MLST", 500],
#	["MLST", 550],
#	["MODE", 502],
#	["NLST", 550],
#	["OPTS", 501],
#	["REST", 200],
#	["SITE", 502],
#	["SIZE", 500],
#	["STOR", 550],
#	["SYST", 530],

	["<init>", 0], # unexpected command-reply pair
	["<missing>", 0], # unexpected command-reply pair
	["QUIT", 0], # unexpected command-reply pair
} &redef;

global ftp_unexpected_cmd_reply: set[string];

type ftp_cmd_arg: record {
	cmd: string;
	arg: string;
	anonymized_cmd: string;
	anonymized_arg: string;	# anonymized arg
	seq: count;		# seq number
	rewrite_slot: count;
};

type ftp_pending_cmds: record {
	seq: count;
	cmds: table[count] of ftp_cmd_arg;
};

function init_ftp_pending_cmds(): ftp_pending_cmds
	{
	local cmds: table[count] of ftp_cmd_arg;
	return [$seq = 1, $cmds = cmds];
	}

function ftp_cmd_pending(s: ftp_pending_cmds): bool
	{
	return length(s$cmds) > 0;
	}

function add_to_ftp_pending_cmds(s: ftp_pending_cmds, cmd: string, arg: string)
	: ftp_cmd_arg
	{
	local ca = [$cmd = cmd, $arg = arg, $anonymized_cmd = "<TBD!>",
			$anonymized_arg = "<TBD!>", $seq = s$seq,
			$rewrite_slot = 0];

	s$cmds[s$seq] = ca;
	++s$seq;

	return ca;
	}

function find_ftp_pending_cmd(s: ftp_pending_cmds, reply_code: count, reply_msg: string): ftp_cmd_arg
	{
	if ( length(s$cmds) == 0 )
		{
		return [$cmd = "<unknown>", $arg = "",
			$anonymized_cmd = "<TBD!>", $anonymized_arg = "<TBD!>",
			$seq = 0, $rewrite_slot = 0];
		}

	local best_match: ftp_cmd_arg;
	local best_score: int = -1;

	for ( seq in s$cmds )
		{
		local ca = s$cmds[seq];
		local score: int = 0;
		# if the command is compatible with the reply code
		# code 500 (syntax error) is compatible with all commands
		if ( reply_code == 500 || [ca$cmd, reply_code] in ftp_cmd_reply_code )
			score = score + 100;
		# if the command or the command arg appears in the reply message
		if ( strstr(reply_msg, ca$cmd) > 0 )
			score = score + 20;
		if ( strstr(reply_msg, ca$cmd) > 0 )
			score = score + 10;
		if ( score > best_score ||
		     ( score == best_score && ca$seq < best_match$seq ) ) # break tie with sequence number
			{
			best_score = score;
			best_match = ca;
			}
		}

	if ( [best_match$cmd, reply_code] !in ftp_cmd_reply_code )
		{
		local annotation = "";
		if ( length(s$cmds) == 1 )
			annotation = "for sure";
		else
			{
			for ( i in s$cmds )
				annotation = cat(annotation, " ", s$cmds[i]$cmd);
			annotation = cat("candidates:", annotation);
			}
		# add ftp_unexpected_cmd_reply[fmt("[\"%s\", %d], # %s",
		#	best_match$cmd, reply_code, annotation)];
		}

	return best_match;
	}

function pop_from_ftp_pending_cmd(s: ftp_pending_cmds, ca: ftp_cmd_arg): bool
	{
	if ( ca$seq in s$cmds )
		{
		delete s$cmds[ca$seq];
		return T;
		}
	else
		return F;
	}

event bro_done()
	{
	# for ( cmd_reply in ftp_unexpected_cmd_reply )
	# 	print ftp_cmd_reply_log, fmt("        %s", cmd_reply);
	}
