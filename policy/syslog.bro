redef capture_filters += { ["syslog"] = "port 514" };

global syslog_ports = { 514/udp } &redef;
redef dpd_config += { [ANALYZER_SYSLOG_BINPAC] = [$ports = syslog_ports] };

module Syslog;

export {
	#redef enum Notice += { 
	#	Syslog_New_Source,
	#	Syslog_New_Destination,
	#};
	
	const facility_codes: table[count] of string = {
		[0]  = "KERN",
		[1]  = "USER",
		[2]  = "MAIL",
		[3]  = "DAEMON",
		[4]  = "AUTH",
		[5]  = "SYSLOG",
		[6]  = "LPR",
		[7]  = "NEWS",
		[8]  = "UUCP",
		[9]  = "CRON",
		[10] =  "AUTHPRIV",
		[11] =  "FTP",
		[12] =  "NTP",
		[13] =  "AUDIT",
		[14] =  "ALERT",
		[15] =  "CLOCK",
		[16] =  "LOCAL0",
		[17] =  "LOCAL1",
		[18] =  "LOCAL2",
		[19] =  "LOCAL3",
		[20] =  "LOCAL4",
		[21] =  "LOCAL5",
		[22] =  "LOCAL6",
		[23] =  "LOCAL7",
	};
	
	const severity_codes: table[count] of string = {
		[0] = "EMERG",
		[1] = "ALERT",
		[2] = "CRIT",
		[3] = "ERR",
		[4] = "WARNING",
		[5] = "NOTICE",
		[6] = "INFO",
		[7] = "DEBUG",
	};
	
}

event syslog_message(c: connection, facility: count, severity: count, msg: string)
	{
	print msg;	
	}
