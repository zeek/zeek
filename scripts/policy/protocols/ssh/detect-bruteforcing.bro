##! Detect hosts which are doing password guessing attacks and/or password
##! bruteforcing over SSH.

@load base/protocols/ssh
@load base/frameworks/metrics
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
	
	redef enum Metrics::ID  += {
		## Metric is to measure failed logins.
		FAILED_LOGIN,
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

	## Tracks hosts identified as guessing passwords.
	global password_guessers: set[addr] 
		&read_expire=guessing_timeout+1hr &synchronized &redef;
}

event bro_init()
	{
	Metrics::add_filter(FAILED_LOGIN, [$name="detect-bruteforcing", $log=F,
	                                   $note=Password_Guessing,
	                                   $notice_threshold=password_guesses_limit,
	                                   $notice_freq=1hr,
	                                   $break_interval=guessing_timeout]);
	}

event SSH::heuristic_successful_login(c: connection)
	{
	local id = c$id;
	
	# TODO: This is out for the moment pending some more additions to the 
	#       metrics framework.
	#if ( id$orig_h in password_guessers )
	#	{
	#	NOTICE([$note=Login_By_Password_Guesser,
	#	        $conn=c,
	#	        $msg=fmt("Successful SSH login by password guesser %s", id$orig_h)]);
	#	}
	}

event SSH::heuristic_failed_login(c: connection)
	{
	local id = c$id;
	
	# Add data to the FAILED_LOGIN metric unless this connection should 
	# be ignored.
	if ( ! (id$orig_h in ignore_guessers &&
	        id$resp_h in ignore_guessers[id$orig_h]) )
		Metrics::add_data(FAILED_LOGIN, [$host=id$orig_h], 1);
	}
