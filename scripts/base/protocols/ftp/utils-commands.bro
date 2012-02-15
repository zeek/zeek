module FTP;

export {
	type CmdArg: record {
		## Time when the command was sent.
		ts:   time;
		## Command.
		cmd:  string &default="<unknown>";
		## Argument for the command if one was given.
		arg:  string &default="";
		## Counter to track how many commands have been executed.
		seq:  count &default=0;
	};
	
	## Structure for tracking pending commands in the event that the client
	## sends a large number of commands before the server has a chance to 
	## reply.
	type PendingCmds: table[count] of CmdArg;
	
	## Possible response codes for a wide variety of FTP commands.
	const cmd_reply_code: set[string, count] = {
		# According to RFC 959
		["<init>", [120, 220, 421]],
		["USER", [230, 331, 332, 421, 530, 500, 501]],
		["PASS", [230, 202, 332, 421, 530, 500, 501, 503]],
		["ACCT", [230, 202, 421, 530, 500, 501, 503]],
		["CWD",  [250, 421, 500, 501, 502, 530, 550]],
		["CDUP", [200, 250, 421, 500, 501, 502, 530, 550]],
		["SMNT", [202, 250, 421, 500, 501, 502, 530, 550]],
		["REIN", [120, 220, 421, 500, 502]],
		["QUIT", [221, 500]],
		["PORT", [200, 421, 500, 501, 530]],
		["PASV", [227, 421, 500, 501, 502, 530]],
		["MODE", [200, 421, 500, 501, 502, 504, 530]],
		["TYPE", [200, 421, 500, 501, 504, 530]],
		["STRU", [200, 421, 500, 501, 504, 530]],
		["ALLO", [200, 202, 421, 500, 501, 504, 530]],
		["REST", [200, 350, 421, 500, 501, 502, 530]],
		["STOR", [110, 125, 150, 226, 250, 421, 425, 426, 451, 551, 552, 532, 450, 452, 553, 500, 501, 530, 550]],
		["STOU", [110, 125, 150, 226, 250, 421, 425, 426, 451, 551, 552, 532, 450, 452, 553, 500, 501, 530, 550]],
		["RETR", [110, 125, 150, 226, 250, 421, 425, 426, 451, 450, 500, 501, 530, 550]],
		["LIST", [125, 150, 226, 250, 421, 425, 426, 451, 450, 500, 501, 502, 530, 550]],
		["NLST", [125, 150, 226, 250, 421, 425, 426, 451, 450, 500, 501, 502, 530, 550]],
		["APPE", [125, 150, 226, 250, 421, 425, 426, 451, 551, 552, 532, 450, 550, 452, 553, 500, 501, 502, 530]],
		["RNFR", [350, 421, 450, 550, 500, 501, 502, 530]],
		["RNTO", [250, 421, 532, 553, 500, 501, 502, 503, 530]],
		["DELE", [250, 421, 450, 550, 500, 501, 502, 530]],
		["RMD",  [250, 421, 500, 501, 502, 530, 550]],
		["MKD",  [257, 421, 500, 501, 502, 530, 550]],
		["PWD",  [257, 421, 500, 501, 502, 550]],
		["ABOR", [225, 226, 421, 500, 501, 502]],
		["SYST", [215, 421, 500, 501, 502, 530]],
		["STAT", [211, 212, 213, 421, 450, 500, 501, 502, 530]],
		["HELP", [200, 211, 214, 421, 500, 501, 502]],
		["SITE", [200, 202, 214, 500, 501, 502, 530]],
		["NOOP", [200, 421, 500]],

		# Extensions
		["LPRT", [500, 501, 521]],                # RFC1639
		["FEAT", [211, 500, 502]],                # RFC2389
		["OPTS", [200, 451, 501]],                # RFC2389
		["EPSV", [229, 500, 501]],                # RFC2428
		["EPRT", [200, 500, 501, 522]],           # RFC2428
		["SIZE", [213, 500, 501, 550]],           # RFC3659
		["MDTM", [213, 500, 501, 550]],           # RFC3659
		["MLST", [150, 226, 250, 500, 501, 550]], # RFC3659
		["MLSD", [150, 226, 250, 500, 501, 550]], # RFC3659
		
		["CLNT", [200, 500]],           # No RFC (indicate client software)
		["MACB", [200, 500, 550]],      # No RFC (test for MacBinary support)

		["<init>", 0],    # unexpected command-reply pair
		["<missing>", 0], # unexpected command-reply pair
		["QUIT", 0],      # unexpected command-reply pair
	} &redef;
}

function add_pending_cmd(pc: PendingCmds, cmd: string, arg: string): CmdArg
	{
	local ca = [$cmd = cmd, $arg = arg, $seq=|pc|+1, $ts=network_time()];
	pc[ca$seq] = ca;
	
	return ca;
	}

# Determine which is the best command to match with based on the 
# response code and message.
function get_pending_cmd(pc: PendingCmds, reply_code: count, reply_msg: string): CmdArg
	{
	local best_match: CmdArg;
	local best_seq = 0;
	local best_score: int = -1;

	for ( cmd_seq in pc )
		{
		local cmd = pc[cmd_seq];
		local score: int = 0;
		
		# if the command is compatible with the reply code
		# code 500 (syntax error) is compatible with all commands
		if ( reply_code == 500 || [cmd$cmd, reply_code] in cmd_reply_code )
			score = score + 100;
		
		# if the command or the command arg appears in the reply message
		if ( strstr(reply_msg, cmd$cmd) > 0 )
			score = score + 20;
		if ( strstr(reply_msg, cmd$arg) > 0 )
			score = score + 10;
		
		if ( score > best_score ||
		     ( score == best_score && best_seq > cmd_seq ) ) # break tie with sequence number
			{
			best_score = score;
			best_seq = cmd_seq;
			best_match = cmd;
			}
		}

	#if ( [best_match$cmd, reply_code] !in cmd_reply_code )
	#	{
	#	# TODO: maybe do something when best match doesn't have an expected response code?
	#	}
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
