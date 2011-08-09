
module Software;

export {
	redef enum Notice::Type += {
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
		NOTICE([$note=Vulnerable_Version, $src=rec$host, $msg=software_fmt(rec)]);
		}
	}