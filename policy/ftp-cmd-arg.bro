module FTP;

export {
	type CmdArg: record {
		cmd:  string &default="<unknown>";
		arg:  string &default="";
		seq:  count &default=0;
	};

	type PendingCmds: table[count] of CmdArg;

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
		#["SIZE", [213, 550]],
		#["SITE", 214],
		#["MDTM", 213],
		#["EPSV", 500],
		#["FEAT", 500],
		#["OPTS", 500],
    
		#["CDUP", 250],
		#["CLNT", 200],
		#["CLNT", 500],
		#["EPRT", 500],
    
		#["FEAT", 211],
		#["HELP", 200],
		#["LIST", 550],
		#["LPRT", 500],
		#["MACB", 500],
		#["MDTM", 212],
		#["MDTM", 500],
		#["MDTM", 501],
		#["MDTM", 550],
		#["MLST", 500],
		#["MLST", 550],
		#["MODE", 502],
		#["NLST", 550],
		#["OPTS", 501],
		#["REST", 200],
		#["SITE", 502],
		#["SIZE", 500],
		#["STOR", 550],
		#["SYST", 530],

		["<init>", 0], # unexpected command-reply pair
		["<missing>", 0], # unexpected command-reply pair
		["QUIT", 0], # unexpected command-reply pair
	} &redef;
}

function add_pending_cmd(pc: PendingCmds, cmd: string, arg: string): CmdArg
	{
	local ca = [$cmd = cmd, $arg = arg, $seq=|pc|+1];
	pc[|pc|+1] = ca;
	
	return ca;
	}

function get_pending_cmd(pc: PendingCmds, reply_code: count, reply_msg: string): CmdArg
	{
	local best_match: CmdArg;
	local best_seq = 0;
	local best_score: int = -1;
	
	#if ( |pc| == 0 )
	#	return best_match;

	for ( cmd_seq in pc )
		{
		local cmd = pc[cmd_seq];
		local score: int = 0;
		# if the command is compatible with the reply code
		# code 500 (syntax error) is compatible with all commands
		if ( reply_code == 500 || [cmd$cmd, reply_code] in ftp_cmd_reply_code )
			score = score + 100;
		# if the command or the command arg appears in the reply message
		if ( strstr(reply_msg, cmd$cmd) > 0 )
			score = score + 20;
		if ( strstr(reply_msg, cmd$cmd) > 0 )
			score = score + 10;
		if ( score > best_score ||
		     ( score == best_score && best_seq > cmd_seq ) ) # break tie with sequence number
			{
			best_score = score;
			best_seq = cmd_seq;
			best_match = cmd;
			}
		}

	if ( [best_match$cmd, reply_code] !in ftp_cmd_reply_code )
		{
		local annotation = "";
		if ( |pc| == 1 )
			annotation = "for sure";
		else
			{
			for ( i in pc )
				annotation = cat(annotation, " ", pc[i]);
			annotation = cat("candidates:", annotation);
			}
		# add ftp_unexpected_cmd_reply[fmt("[\"%s\", %d], # %s",
		#	best_match$cmd, reply_code, annotation)];
		}

	return best_match;
	}

function remove_pending_cmd(pc: PendingCmds, ca: CmdArg): bool
	{
	if ( ca$seq in pc )
		{
		delete pc[ca$seq];
		return T;
		}
	else
		return F;
	}
	
function pop_pending_cmd(pc: PendingCmds, reply_code: count, reply_msg: string): CmdArg
	{
	local ca = get_pending_cmd(pc, reply_code, reply_msg);
	remove_pending_cmd(pc, ca);
	return ca;
	}
