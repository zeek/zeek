##! Detect various potentially bad FTP activities.

@load base/frameworks/notice
@load base/protocols/ftp

module FTP;

export {
	redef enum Notice::Type += {
		## Indicates that a successful response to a "SITE EXEC"
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
		        $msg=fmt("FTP command: %s %s", c$ftp$cmdarg$cmd, c$ftp$cmdarg$arg),
		        $identifier=cat(c$id$orig_h, c$id$resp_h, "SITE EXEC")]);
		}
	}
