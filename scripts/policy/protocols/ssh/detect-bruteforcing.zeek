##! Detect hosts which are doing password guessing attacks and/or password
##! bruteforcing over SSH.

@load base/protocols/ssh
@load base/frameworks/sumstats
@load base/frameworks/notice
@load base/frameworks/intel

module SSH;

export {
	redef enum Notice::Type += {
		## Indicates that a host has been identified as crossing the
		## :zeek:id:`SSH::password_guesses_limit` threshold with
		## failed logins.
		Password_Guessing,
		## Indicates that a host previously identified as a "password
		## guesser" has now had a successful login
		## attempt. This is not currently implemented.
		Login_By_Password_Guesser,
	};

	redef enum Intel::Where += {
		## An indicator of the login for the intel framework.
		SSH::SUCCESSFUL_LOGIN,
	};

	## The number of failed SSH connections before a host is designated as
	## guessing passwords.
	const password_guesses_limit: double = 30 &redef;

	## The amount of time to remember presumed non-successful logins to
	## build a model of a password guesser.
	const guessing_timeout = 30 mins &redef;

	## This value can be used to exclude hosts or entire networks from being
	## tracked as potential "guessers". The index represents
	## client subnets and the yield value represents server subnets.
	const ignore_guessers: table[subnet] of subnet &redef;
}

event zeek_init()
	{
	local r1: SumStats::Reducer = [$stream="ssh.login.failure", $apply=set(SumStats::SUM, SumStats::SAMPLE), $num_samples=5];
	SumStats::create([$name="detect-ssh-bruteforcing",
	                  $epoch=guessing_timeout,
	                  $reducers=set(r1),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	return result["ssh.login.failure"]$sum;
	                  	},
	                  $threshold=password_guesses_limit,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["ssh.login.failure"];
	                  	local sub_msg = fmt("Sampled servers: ");
	                  	local samples = r$samples;
	                  	for ( i in samples )
	                  		{
	                  		if ( samples[i]?$str )
	                  			sub_msg = fmt("%s%s %s", sub_msg, i==0 ? "":",", samples[i]$str);
	                  		}
	                  	# Generate the notice.
	                  	NOTICE([$note=Password_Guessing,
	                  	        $msg=fmt("%s appears to be guessing SSH passwords (seen in %d connections).", key$host, r$num),
	                  	        $sub=sub_msg,
	                  	        $src=key$host,
	                  	        $identifier=cat(key$host)]);
	                  	}]);
	}

event ssh_auth_successful(c: connection, auth_method_none: bool)
	{
	local id = c$id;

	Intel::seen([$host=id$orig_h,
	             $conn=c,
	             $where=SSH::SUCCESSFUL_LOGIN]);
	}

event ssh_auth_failed(c: connection)
	{
	local id = c$id;

	# Add data to the FAILED_LOGIN metric unless this connection should
	# be ignored.
	if ( ! (id$orig_h in ignore_guessers &&
	        id$resp_h in ignore_guessers[id$orig_h]) )
		SumStats::observe("ssh.login.failure", [$host=id$orig_h], [$str=cat(id$resp_h)]);
	}
