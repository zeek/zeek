##! Constants definitions for syslog.

module Syslog;

export {
	## Mapping between the constants and string values for syslog facilities.
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
	} &default=function(c: count): string { return fmt("?-%d", c); };
	
	## Mapping between the constants and string values for syslog severities.
	const severity_codes: table[count] of string = {
		[0] = "EMERG",
		[1] = "ALERT",
		[2] = "CRIT",
		[3] = "ERR",
		[4] = "WARNING",
		[5] = "NOTICE",
		[6] = "INFO",
		[7] = "DEBUG",
	} &default=function(c: count): string { return fmt("?-%d", c); };
}