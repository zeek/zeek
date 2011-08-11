
module SSH;

export {
	redef enum Notice::Type += {
		## Indicates that a host has been identified as crossing the 
		## :bro:id:`password_guesses_limit` threshold with heuristically
		## determined failed logins.
		Password_Guessing,
		## Indicates that a host previously identified as a "password guesser"
		## has now had a heuristically successful login attempt.
		Login_By_Password_Guesser,
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

	## Keeps count of how many rejections a host has had.
	global password_rejections: table[addr] of TrackCount 
		&write_expire=guessing_timeout
		&synchronized;

	## Keeps track of hosts identified as guessing passwords.
	global password_guessers: set[addr] &read_expire=guessing_timeout+1hr &synchronized;
}

event SSH::heuristic_successful_login(c: connection)
	{
	local id = c$id;
	
	# TODO: this should be migrated to the metrics framework.
	if ( id$orig_h in password_rejections &&
	     password_rejections[id$orig_h]$n > password_guesses_limit &&
	     id$orig_h !in password_guessers )
		{
		add password_guessers[id$orig_h];
		NOTICE([$note=Login_By_Password_Guesser,
		        $conn=c,
		        $n=password_rejections[id$orig_h]$n,
		        $msg=fmt("Successful SSH login by password guesser %s", id$orig_h),
		        $sub=fmt("%d failed logins", password_rejections[id$orig_h]$n)]);
		}
	}

event SSH::heuristic_failed_login(c: connection)
	{
	local id = c$id;
	
	# presumed failure
	if ( id$orig_h !in password_rejections )
		password_rejections[id$orig_h] = new_track_count();
	
	# Track the number of rejections
	# TODO: this should be migrated to the metrics framework.
	if ( ! (id$orig_h in ignore_guessers &&
	        id$resp_h in ignore_guessers[id$orig_h]) )
		++password_rejections[id$orig_h]$n;
	
	if ( default_check_threshold(password_rejections[id$orig_h]) )
		{
		add password_guessers[id$orig_h];
		NOTICE([$note=Password_Guessing,
		        $conn=c,
		        $msg=fmt("SSH password guessing by %s", id$orig_h),
		        $sub=fmt("%d apparently failed logins", password_rejections[id$orig_h]$n),
		        $n=password_rejections[id$orig_h]$n]);
		}
	}