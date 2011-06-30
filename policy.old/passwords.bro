# $Id: passwords.bro 688 2004-11-02 23:59:55Z vern $

# Generates notices of exposed passwords.  Currently just works
# on telnet/rlogin access.  Should be extended to do FTP, HTTP, etc.

@load login

redef enum Notice += {
	PasswordExposed,
};

# Usernames which we ignore.
global okay_usernames: set[string] &redef;

# Passwords which we ignore.
global okay_passwords = { "", "<none>" } &redef;

event login_success(c:connection, user: string, client_user: string,
			password: string, line: string)
	{
	if ( user in okay_usernames || password in okay_passwords )
		return;

	NOTICE([$note=PasswordExposed,
		$conn=c,
		$user=user,
		$sub=password,
		$msg="login exposed user's password"]);
	}
