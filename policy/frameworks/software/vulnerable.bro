@load software/base
@load notice

module Software;

export {
	redef enum Notice::Type += {
		Vulnerable_Version,
	};

	## This is a table of software versions indexed by the name of the 
	## software and yielding the latest version that is vulnerable.
	const vulnerable_versions: table[string] of Version &redef;
}

redef vulnerable_versions += {
	["Flash"] = [$major=10,$minor=2,$minor2=153,$addl="1"],
	["Java"] = [$major=1,$minor=6,$minor2=0,$addl="22"],
};

event log_software(rec: Info)
	{
	if ( rec$name in vulnerable_versions &&
	     cmp_versions(rec$version, vulnerable_versions[rec$name]) <= 0 )
		{
		NOTICE([$note=Vulnerable_Version, $src=rec$host, $msg=software_fmt(rec)]);
		}
	}