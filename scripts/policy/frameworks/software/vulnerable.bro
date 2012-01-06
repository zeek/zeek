##! Provides a variable to define vulnerable versions of software and if a 
##! a version of that software as old or older than the defined version a 
##! notice will be generated.

@load base/frameworks/notice
@load base/frameworks/software

module Software;

export {
	redef enum Notice::Type += {
		## Indicates that a vulnerable version of software was detected.
		Vulnerable_Version,
	};

	## This is a table of software versions indexed by the name of the 
	## software and yielding the latest version that is vulnerable.
	const vulnerable_versions: table[string] of Version &redef;
}

event log_software(rec: Info)
	{
	if ( rec$name in vulnerable_versions &&
	     cmp_versions(rec$version, vulnerable_versions[rec$name]) <= 0 )
		{
		NOTICE([$note=Vulnerable_Version, $src=rec$host, 
		        $msg=fmt("A vulnerable version of software was detected: %s", software_fmt(rec))]);
		}
	}
