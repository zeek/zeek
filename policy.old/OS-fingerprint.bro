# $Id: OS-fingerprint.bro 1071 2005-03-08 14:09:31Z vern $
#
# Tracks operating system versioning using the "software" framework.

@load software

event OS_version_found(c: connection, host: addr, OS: OS_version)
	{
	local version: software_version;
	version$major = version$minor = version$minor2 = -1;
	version$addl = OS$detail;

	local sw: software;
	sw$name = OS$genre;
	sw$version = version;

	event software_version_found(c, host, sw, "OS");
	}
