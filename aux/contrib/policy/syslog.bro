# general syslog analyzer 0.3
#
# NOTES:
# - for now, all IP addresses need to be expressed in IPv4 notation here or it will end up 
#   looking like 255.255.255.255

@load listen-clear
@load listen-ssl
@load user-check

# put something like this in hostname.bro file
#redef Remote::destinations += {
#        ["syslog"] = [$host = 10.0.0.1, $events = /.*/, $connect=F, $retry = 60 secs, $ssl=T],
#};


# list of notices
redef enum Notice += {
	LoginFail, 		# too many failed attempt to a given dest
	LoginFailSrc, 		# num failed logins from source IP exceeds thresh
	LoginFailPair,		# num failed logins from IP pair exceeds thresh
	LoginFailAccount,	# num failed accounts from IP->IP exceeds thresh
	LoginFailAccountPair,	# num failed accounts from IP->account@IP exceeds thresh
	LoginFailDict,		# num failed authentications for IP->account@IP exceeds thresh
	LoginAfterFail,		# succ login after a series of bad from source IP
};

global syslog = open_log_file("syslog") &redef;


# overall design is as follows:
#
# SIP --->table[DIPs] of login_record for each SIP<->DIP
#     --->count of total failed logins for SIP
#     --->count of total failed accounts for SIP
#     access cluster data fia the cluster.bro script since it can
#     deal better with the general notion.  
#
# data will be stored in two tables, one holding global data for the source IP,
# the other holding origIP<->respIP information.  There is likely as better
# way to go about this.

# list of ssh auth_strings to ignore; 
#  gssapi-with-mic: ssh sometimes tries, this, fails, and they
#     uses pass phrase to log in. Dont count this type of failure for now
#     (may need to revisit this later if every see attack using this)
const skip_auth_strings =     {"gssapi-with-mic", } &redef;

### config data ###
const dest_num_fail_logins =     25;	# to a single dest
const source_num_fail_logins =   20;	# across all hosts, from a single source
const source_num_fail_accounts = 20;	# 
const pair_num_fail_logins =     25;	# applies to single IP<->IP sets
const pair_num_fail_accounts =   20;	#

const single_account_fail =      25;	# threshold for a single IP -> account@IP fail
					# works also as dictionary threshold on a single account

### end config data ###

### data structs ###
	# IP<->IP record
	type pair_record: record {
		total_logins: count &default=0;		# failed login count in total
		total_accounts: count &default=0;	# total count of accounts seen
		accounts: table[string] of count;	# running count per unique account
		#peer: set[count];			# event_peer$id for distributed analysis
	};

	# source record
	type source_record: record {
		stotal_logins: count &default=0;
		stotal_accounts: count &default=0;
	};

# table for source data
global source_list: table[addr] of source_record &write_expire  = 24 hr;

# table for pair data
global pair_list: table[addr,addr] of pair_record &write_expire  = 24 hr;

global dests : table[addr] of count &write_expire = 1 hr; 

### end data structs, config and control

### begin functions and events ###

# for the following events, the existance test takes place since
# there is a chance that the postponed_ssh_login has removed the account
# as a problem.  See that event for more information and complaining...

event login_fail_src(ts:double, orig_h:addr)
	{
	# Here we look for the total number of failed accounts assosciated with
	# a source IP.

	# make sure the problem still exists for the host
	if ( orig_h in source_list )
		{
		local srec: source_record = source_list[orig_h];

		if ( srec$stotal_logins >= source_num_fail_logins )
			NOTICE([$note=LoginFailSrc, $src=orig_h,
				$msg=fmt("%s Exceeded %d failed logins to multiple hosts",
					orig_h, source_num_fail_logins)]);
		}
	}

event login_fail_account(ts:double, orig_h:addr, account:string)
	{
	# Here we look at the total number of unique failed accounts assosciated
	# with a given source IP.

	# make sure the problem still exists for the host
	if ( orig_h in source_list )
		{
		local srec: source_record = source_list[orig_h];

		if ( srec$stotal_accounts >= source_num_fail_accounts )
			NOTICE([$note=LoginFailAccount, $src=orig_h,
				$msg=fmt("%s has %s different account attempts to multiple hosts ",
					orig_h, source_num_fail_accounts)]);
		}
	}

event login_fail_pair(ts:double, orig_h:addr, resp_h:addr, account:string)
	{
	# Here we look at the number of failed logins for a pair of IP addresses.

	# make sure the problem still exists for the host
	if ( [orig_h, resp_h] in pair_list )
		{
		local prec: pair_record = pair_list[orig_h, resp_h];

		if ( prec$total_logins >= pair_num_fail_logins )
			NOTICE([$note=LoginFailPair, $src=orig_h, $dst=resp_h,
				 $msg=fmt("%s -> %s Exceeded %s failed logins for %s",
				orig_h, resp_h, prec$total_logins, account)]);

		}
	}

event login_fail_account_pair(ts:double, orig_h:addr, resp_h:addr, account:string)
	{
	# Here we look at the number of failed accounts per IP pair.

	if ( [orig_h, resp_h] in pair_list )
		{
		local prec: pair_record = pair_list[orig_h, resp_h];

		if ( prec$total_logins >= pair_num_fail_accounts )
			NOTICE([$note=LoginFailAccountPair, $src=orig_h, $dst=resp_h,
				$msg=fmt("%s -> %s Exceeded %s failed accounts",
				orig_h, resp_h, prec$total_accounts)]);
		}
	}

event login_fail_dict(ts:double, orig_h:addr, resp_h:addr, account:string)
	{
	# Here we look at the number of times an account has failed for a given IP
	# pair.  This is looking in particular for dictionary attacks

	if ( [orig_h, resp_h] in pair_list )
		{
		local prec: pair_record = pair_list[orig_h, resp_h];
		
		# make sure that the account is still there
		if ( account in prec$accounts )
			{
			if ( prec$accounts[account] >= single_account_fail )
				# *finally* we are able to send the notice.  seems
				# like a lot of work...
				NOTICE([$note=LoginFailDict, $src=orig_h, $dst=resp_h,
					$msg=fmt("%s -> %s@%s Exceeded %s failed tries",
						orig_h, account, resp_h, prec$accounts[account])]);
			}
		} # end pair check
	}


event ssh_login(ts:double, orig_h:addr, resp_h:addr, account:string, auth_type:string)
	{
        print syslog, fmt("%.1f ssh_login %s -> %s@%s  %s", ts, orig_h, account, resp_h, auth_type);

	local prec: pair_record;

	# run a basic check on the user
	check_user(ts, orig_h, resp_h, account, auth_type);

	if ( [orig_h,resp_h] in pair_list )
		{
		# we have seen the pair, have we seen the account?
		prec = pair_list[orig_h, resp_h];
		
		if ( account in prec$accounts )
			{
			# there is a history of failure, check threshold.  Also skip the
			# informational accounts since there is a great deal of noise with them
			if ( (prec$accounts[account] == single_account_fail) && (!informational_user(account)) )
				{
				NOTICE([$note=LoginAfterFail, $src=orig_h, $dst=resp_h,
					$msg=fmt("%s -> %s@%s user login after %s failed logins ",
						orig_h, account, resp_h, single_account_fail)]);
				}
			}
		}	
	else
		{
		# add new pair list
		local tmp_accounts: table[string] of count;
		tmp_accounts[account] = 1;
		
		prec$total_logins = 1;
		prec$total_accounts = 1;
		prec$accounts = tmp_accounts;

		pair_list[orig_h, resp_h] = prec;
		}

	} # end ssh_ok_login

event ssh_fail_login(ts:double, orig_h:addr, resp_h:addr, account:string, auth_type:string)
	{
	local prec: pair_record;
	local srec: source_record;

	print syslog, fmt("%.1f ssh_fail_login %s -> %s@%s  %s", ts, orig_h, account, resp_h, auth_type);

        if (auth_type in skip_auth_strings )
        {
	        print syslog, fmt("ignoring ssh_fail: %s", auth_type);
		return;
        }

	# run a basic check on the user
	check_user(ts, orig_h, resp_h, account, "ssh_fail");

	# there are a number of accounts that are infrastructural in nature
	# and used internally.  We skip them for now even though this is 
	# probably not such a good idea

	# include local addrs too and see what happens
	#if ( (!is_local_addr(orig_h)) && (!informational_user(account)) )

	if ( (!informational_user(account)) )
		{
		# look at dest 
		if ( resp_h !in dests )
		    dests[resp_h] = 0;
	        ++dests[resp_h];

		if (dests[resp_h] == dest_num_fail_logins)
			NOTICE([$note=LoginFail, $src=orig_h, $dst=resp_h,
				$msg=fmt("Exceeded %d failed logins from %s to %s",
					dest_num_fail_logins, orig_h, resp_h)]);

		if ( orig_h !in source_list )
			{ # add a new record
			srec$stotal_logins = 1;
			srec$stotal_accounts = 1;

			source_list[orig_h] = srec;
			}
		else
			{	
			srec = source_list[orig_h];

			# schedule an event to trigger the notice to provide an opportunity
			# to correct for pam running thorough 'false negatives'
			if ( ++srec$stotal_logins == source_num_fail_logins )
				schedule 10 sec { login_fail_src(ts, orig_h) };

			# for the time being this is being commented out ...
			#if ( ++srec$stotal_accounts == source_num_fail_accounts ) 
			#	schedule 10 sec { login_fail_account(ts, orig_h, account) };
			}

		# look at pair
		if ( [orig_h, resp_h] !in pair_list )
			{
			local tmp_accounts: table[string] of count; 
			tmp_accounts[account] = 1;

			prec$total_logins = 1;
			prec$total_accounts = 1;
			prec$accounts = tmp_accounts;

			}
		else
			{
			prec = pair_list[orig_h, resp_h];

			# this is a gross evaluation of the total login failures between two hosts
			# which is really the sum of all failures - accounts single or multiple
			if ( ++prec$total_logins == pair_num_fail_logins )
				schedule 10 sec 
					{ 
					login_fail_pair(ts, orig_h, resp_h, account) 
					};
		
			# have we seen the account before?
			if ( account !in prec$accounts )
				{
				prec$accounts[account] = 1;

				# look for multiple failures for many accounts: increment since this is new
				if ( ++prec$total_accounts == pair_num_fail_accounts )
					schedule 10 sec 
						{ 
						login_fail_account_pair(ts, orig_h, resp_h, account) 
						};
				}
			else
				{
				# look for multiple failures for a single account
				if ( ++prec$accounts[account] == single_account_fail )
					schedule 10 sec 
						{ 
						login_fail_dict(ts, orig_h, resp_h, account) 
						}; 
				}
			}

			# update data
		        #print "syslog: ssh_fail, updating source_list and pair_list ", srec, prec;
			source_list[orig_h] = srec;
			pair_list[orig_h, resp_h] = prec;

		} # end initial internal/user filter
			
	}

event postponed_ssh_login(ts:double, orig_h:addr, resp_h:addr, account:string, auth_type:string)
	{
	# This abomination is a result of a login passing through pam and ssh sending
	# sperious 'failed' messages with the final successful login message.
	# Here we intercept the data before the scheduled NOTICE event and change it back. 
	# This is a prime example of how to introduce race conditions into code, but for the time 
	# being I have nothing better.

	print syslog, fmt("%.1f postponed_ssh_login %s -> %s@%s  %s", ts, orig_h, account, resp_h, auth_type);

	# this code is almost the same as above except that we are removing values (which introduces 
	# more testing).
	local prec: pair_record;
	local srec: source_record;
	local delta: count = 2; # ammount to decrement 

	# look at source, skip if record does not exist
	if ( orig_h in source_list )
		{	
		srec = source_list[orig_h];

		if ( (srec$stotal_logins - delta) >= 0 ) 
			srec$stotal_logins = srec$stotal_logins - delta;

		if ( (srec$stotal_accounts - delta) >= 0 )
			srec$stotal_accounts = srec$stotal_logins - delta;
		}

	# look at pair, again skipping unknown sessions (throw weird?)
	if ( [orig_h, resp_h] in pair_list )
		{
		prec = pair_list[orig_h, resp_h];

		if ( (prec$total_logins - delta) >= 0 ) 
			prec$total_logins = prec$total_logins - delta;
		
		if ( (prec$total_accounts - delta) >= 0 )
			prec$total_accounts = prec$total_logins - delta;

		if ( account in prec$accounts )
			{
			if ( (prec$accounts[account] - delta) >= 0 )  
				prec$accounts[account] = prec$accounts[account] - delta;
			}
		} # end pair check

		source_list[orig_h] = srec;
		pair_list[orig_h, resp_h] = prec;


	} # end of postpend

# really want both users, waiting for fix..
#event failed_su(ts:double, orig_h:addr, user:string, user2:string)
event failed_su(ts:double, orig_h:addr, user:string)
{
        #print syslog, fmt("%.1f failed_su %s %s", ts, orig_h, user, user2 );
        print syslog, fmt("%.1f failed_su %s %s", ts, orig_h, user);
	# should generate a notice if too many of these
}

event successful_su (ts:double, orig_h:addr, logname: string, user:string  )
{
        print syslog, fmt("%.1f sucussful_su %s %s to %s", ts, orig_h, logname, user );
}

event failed_sudo (ts:double, orig_h:addr, user:string )
{
        print syslog, fmt("%.1f failed_sudo %s@%s", ts, user, orig_h );
	# should generate a notice if too many of these
}

event successful_sudo (ts:double, orig_h:addr, user:string, command:string)
{
        print syslog, fmt("%.1f sucussful_sudo %s@%s %s", ts, user, orig_h, command );
}

#other syslog events: Grid stuff
#"gateInit double=$time addr=$runhost addr=$reqhost count=$p \n";
#"gateUser addr=$runhost count=$p2 string=$IDFields[9]\n";
#"gateService addr=$runhost count=$p2 string=$srvFields[8]\n";
#"gateLocalUser addr=$runhost count=$p2 string=$LUFields [10] string=$LUFields[6]\n";
#"gateLocalUID addr=$runhost count=$p2 count=$LUFields[10] string=$LUFields[6]\n";
#print "gateLocalGID addr=$runhost count=$p2 count=$GUFields[9]\n";


