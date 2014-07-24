module SMB;

export {
	redef enum Log::ID += {
		ATSVC_LOG,
	};

	type ATSvcInfo: record {
	## Time of the request
	ts	: time &log;
	## UID of the connection
	uid	: string &log;
	## Connection info
	id	: conn_id &log;
	## Command (add, enum, delete, etc.)
	command : string &log;
	## Argument
	arg	: string &log;
	## Server the command was issued to
	server	: string &log;
	## Result of the command
	result	: string &log &optional;
	};
}

redef record connection += {
	smb_atsvc: ATSvcInfo &optional;
};

event bro_init() &priority=5
	{
	Log::create_stream(ATSVC_LOG, [$columns=ATSvcInfo]);
	}

event smb_atsvc_job_add(c: connection, server: string, job: string)
	{
	local info: ATSvcInfo;
	info$ts = network_time();
	info$uid = c$uid;
	info$id = c$id;
	info$command = "Add job";
	info$arg = job;
	info$server = server;

	c$smb_atsvc = info;
	}

event smb_atsvc_job_id(c: connection, id: count, status: count)
	{
	if ( !c?$smb_atsvc )
		return;
	if ( status == 0 )
		c$smb_atsvc$result = "success";
	else
		c$smb_atsvc$result = "failed";

	Log::write(ATSVC_LOG, c$smb_atsvc);
	delete c$smb_atsvc;
	}