@load syslog

module Syslog;

export {
	# If set to T, this will split inbound and outbound transactions
	# into separate files.  F merges everything into a single file.
	const split_log_file = F &redef;
	
	# Which SSH logins to record.
	# Choices are: Inbound, Outbound, Enabled, Disabled
	const logging = Enabled &redef;
	
}

event bro_init()
	{
	LOG::create_logs("syslog", logging, split_log_file, T);
	LOG::define_header("syslog", cat_sep("\t", "", 
	                                     "ts",
	                                     "orig_h", "orig_p",
	                                     "resp_h", "resp_p",
	                                     "facility", "severity",
	                                     "msg"));
	}
	
event syslog_message(c: connection, facility: count, severity: count, msg: string)
	{
	local log = LOG::get_file_by_id("syslog", c$id, F);
	local id = c$id;
	
	print log, cat_sep("\t", "\\N",
	                   network_time(),
	                   id$orig_h, port_to_count(id$orig_p),
	                   id$resp_h, port_to_count(id$resp_p),
	                   facility_codes[facility], severity_codes[severity],
	                   msg);
	}
