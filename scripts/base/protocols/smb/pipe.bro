module SMB;

export {
	redef enum Log::ID += {
		ATSVC_LOG,
	};

	type ATSvcInfo: record {
		ts       : time    &log; ##< Time of the request
		uid      : string  &log; ##< UID of the connection
		id       : conn_id &log; ##< Connection info
		command  : string  &log; ##< Command (add, enum, delete, etc.)
		arg      : string  &log; ##< Argument
		server   : string  &log; ##< Server the command was issued to
		result   : string  &log &optional; ##< Result of the command
	};
}

redef record SMB::State += {
	pipe_atsvc: ATSvcInfo &optional;
};

event bro_init() &priority=5
	{
	Log::create_stream(ATSVC_LOG, [$columns=ATSvcInfo]);
	}

event smb_atsvc_job_add(c: connection, server: string, job: string) &priority=5
	{
	local info = ATSvcInfo($ts=network_time(),
	                       $uid = c$uid,
	                       $id = c$id,
	                       $command = "Add job",
	                       $arg = job,
	                       $server = server);
	c$smb_state$pipe_atsvc = info;
	}

event smb_atsvc_job_id(c: connection, id: count, status: count) &priority=5
	{
	if ( c$smb_state?$pipe_atsvc )
		c$smb_state$pipe_atsvc$result = (status==0) ? "success" : "failed";
	}

event smb_atsvc_job_id(c: connection, id: count, status: count) &priority=-5
	{
	if ( c$smb_state?$pipe_atsvc )
		{
		Log::write(ATSVC_LOG, c$smb_state$pipe_atsvc);
		delete c$smb_state$pipe_atsvc;
		}
	}