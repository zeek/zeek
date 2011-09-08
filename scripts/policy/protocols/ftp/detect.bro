@load base/frameworks/notice/main
@load base/protocols/ftp/main

module FTP;

export {
	redef enum Notice::Type += {
		## This indicates that a successful response to a "SITE EXEC" 
		## command/arg pair was seen.
		Site_Exec_Success,
	};
}

event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool) &priority=3
	{
	local response_xyz = parse_ftp_reply_code(code);
	
	# If a successful SITE EXEC command is executed, raise a notice.
	if ( response_xyz$x == 2 &&
	     c$ftp$cmdarg$cmd == "SITE" && 
	     /[Ee][Xx][Ee][Cc]/ in c$ftp$cmdarg$arg )
		{
		NOTICE([$note=Site_Exec_Success, $conn=c,
		        $msg=fmt("%s %s", c$ftp$cmdarg$cmd, c$ftp$cmdarg$arg)]);
		}
	}
