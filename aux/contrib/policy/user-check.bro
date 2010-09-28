# version 0.1
# script to make detailed decisions about user logins
#
# there are three levels of interest - 
# 	informational : general interest (say root) for account use
# 	suspicious : specific accounts that you do not
# 	   expect to see and should know (such as 'lp')
#	dead_man_walkin : accounts that may represent former employies 
#	   or known bad entities.
#
# the choice to differentiate between the second and third may be gratuitious...
#
#

redef enum Notice += {
	SuspiciousUser,		# a user is seen that should not normally be there
	ForbiddenUser,	        # known bad user account, more dangerous than suspicous
	SensitiveRemoteLogin,        # root ssh connection from remote host
};

global check_dead_man_walkin = T &redef; 
global check_user_list = T &redef;
global check_remote_access_accounts = T &redef;

# this one not finished: might want to flag these someday
const information_accounts = { "operator", } &redef;

const suspicious_accounts = { "lp", "toor", "admin", "test", "r00t", "bash", } &redef;

const forbidden_accounts = { "", } &redef;

# this is for accounts that you do not want logging in remotely 
const no_remote_accounts = { "root", "system", "operator", } &redef; 

function informational_user(user: string) : bool
	{
	if ( user in information_accounts )
		return T;

	return F;
	}

function check_user(ts:double, orig_h:addr, resp_h:addr, account:string, auth_type:string) : bool
	{

	# compare provided user with a list of potential bad accounts
	# see note above about hot-ids: this provides a little better 
	# flexability for general checking
	#

        #print "checking user: ", account;

	if ( check_dead_man_walkin && account in forbidden_accounts )
		{
		NOTICE([$note=ForbiddenUser,
			$msg=fmt("%s -> %s@%s forbidden user login",
				 orig_h, account, resp_h)]);

		return T;
		}

	if ( check_user_list && account in suspicious_accounts )
		{
		NOTICE([$note=SuspiciousUser,
			$msg=fmt("%s -> %s@%s suspicious user login",
				orig_h, account, resp_h)]);
		return T;
		}

	if ( check_remote_access_accounts && account in no_remote_accounts 
			&& !is_local_addr(orig_h) && auth_type != "ssh_fail" )
		{
		NOTICE([$note=SensitiveRemoteLogin,
			$msg=fmt("%s -> %s@%s successful sensitive remote login",
				orig_h, account, resp_h)]);
		return T;
		}

	return F;
		
	}

