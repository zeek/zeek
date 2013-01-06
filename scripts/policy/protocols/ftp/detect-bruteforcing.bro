
@load base/protocols/ftp
@load base/frameworks/metrics

@load base/utils/time

module FTP;

export {
	redef enum Notice::Type += { 
		## Indicates a host bruteforcing FTP logins by watching for too many
		## rejected usernames or failed passwords.
		Bruteforcing
	};

	## How many rejected usernames or passwords are required before being 
	## considered to be bruteforcing.
	const bruteforce_threshold = 20 &redef;

	## The time period in which the threshold needs to be crossed before
	## being reset.
	const bruteforce_measurement_interval = 15mins;
}


event bro_init()
	{
	Metrics::add_filter("ftp.failed_auth", [$every=bruteforce_measurement_interval,
	                                        $measure=set(Metrics::UNIQUE),
	                                        $threshold_val_func(val: Metrics::ResultVal) = { return val$num; },
	                                        $threshold=bruteforce_threshold,
	                                        $threshold_crossed(index: Metrics::Index, val: Metrics::ResultVal) = 
	                                        	{
	                                        	local dur = duration_to_mins_secs(val$end-val$begin);
	                                        	local message = fmt("%s had %d failed logins on %d FTP servers in %s", index$host, val$num, val$unique, dur);
	                                        	NOTICE([$note=FTP::Bruteforcing, 
	                                        	        $src=index$host,
	                                        	        $msg=message,
	                                        	        $identifier=cat(index$host)]);
	                                        	}]);
	}

event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
	{
	local cmd = c$ftp$cmdarg$cmd;
	if ( cmd == "USER" || cmd == "PASS" )
		{
		if ( FTP::parse_ftp_reply_code(code)$x == 5 )
			Metrics::add_data("ftp.failed_auth", [$host=c$id$orig_h], [$str=cat(c$id$resp_h)]);
		}
	}