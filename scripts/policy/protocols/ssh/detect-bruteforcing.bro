##! Detect hosts which are doing password guessing attacks and/or password
##! bruteforcing over SSH.

@load base/protocols/ssh
@load base/frameworks/measurement
@load base/frameworks/notice
@load base/frameworks/intel

module SSH;

export {
	redef enum Notice::Type += {
		## Indicates that a host has been identified as crossing the 
		## :bro:id:`SSH::password_guesses_limit` threshold with heuristically
		## determined failed logins.
		Password_Guessing,
		## Indicates that a host previously identified as a "password guesser"
		## has now had a heuristically successful login attempt.  This is not
		## currently implemented.
		Login_By_Password_Guesser,
	};

	redef enum Intel::Where += {
		## An indicator of the login for the intel framework.
		SSH::SUCCESSFUL_LOGIN,
	};
	
	## The number of failed SSH connections before a host is designated as
	## guessing passwords.
	const password_guesses_limit = 30 &redef;

	## The amount of time to remember presumed non-successful logins to build
	## model of a password guesser.
	const guessing_timeout = 30 mins &redef;

	## This value can be used to exclude hosts or entire networks from being 
	## tracked as potential "guessers".  There are cases where the success
	## heuristic fails and this acts as the whitelist.  The index represents 
	## client subnets and the yield value represents server subnets.
	const ignore_guessers: table[subnet] of subnet &redef;
}

event bro_init()
	{
	Metrics::add_filter("ssh.login.failure", [$name="detect-bruteforcing", $log=F,
	                                          $every=guessing_timeout,
	                                          $measure=set(Metrics::SUM),
	                                          $threshold=password_guesses_limit,
	                                          $threshold_crossed(index: Metrics::Index, val: Metrics::ResultVal) = {
	                                          	# Generate the notice.
	                                          	NOTICE([$note=Password_Guessing, 
	                                          	        $msg=fmt("%s appears to be guessing SSH passwords (seen in %.0f connections).", index$host, val$sum),
	                                          	        $src=index$host,
	                                          	        $identifier=cat(index$host)]);
	                                          	# Insert the guesser into the intel framework.
	                                          	Intel::insert([$host=index$host,
	                                          	               $meta=[$source="local", 
	                                          	                      $desc=fmt("Bro observed %0.f apparently failed SSH connections.", val$sum)]]);
	                                          }]);
	}

event SSH::heuristic_successful_login(c: connection)
	{
	local id = c$id;
	
	Intel::seen([$host=id$orig_h,
	             $conn=c,
	             $where=SSH::SUCCESSFUL_LOGIN]);
	}

event SSH::heuristic_failed_login(c: connection)
	{
	local id = c$id;
	
	# Add data to the FAILED_LOGIN metric unless this connection should 
	# be ignored.
	if ( ! (id$orig_h in ignore_guessers &&
	        id$resp_h in ignore_guessers[id$orig_h]) )
		Metrics::add_data("ssh.login.failure", [$host=id$orig_h], [$num=1]);
	}
