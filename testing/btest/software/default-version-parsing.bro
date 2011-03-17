# @TEST-EXEC: bro %INPUT > output
# @TEST-EXEC: btest-diff output

@load software

global ts = network_time();
global matched_software: table[string] of Software::Info = {
	["OpenSSH_4.4"] = 
		[$name="OpenSSH", $version=[$major=4,$minor=4], $host=0.0.0.0, $ts=ts],
	["OpenSSH_5.2"] = 
		[$name="OpenSSH", $version=[$major=5,$minor=2], $host=0.0.0.0, $ts=ts],
	["Apache/2.0.63 (Unix) mod_auth_kerb/5.3 mod_ssl/2.0.63 OpenSSL/0.9.7a mod_fastcgi/2.4.2"] =
		[$name="Apache", $version=[$major=2,$minor=0,$minor2=63,$addl="Unix"], $host=0.0.0.0, $ts=ts],
	["Apache/1.3.19 (Unix)"] =
		[$name="Apache", $version=[$major=1,$minor=3,$minor2=19,$addl="Unix"], $host=0.0.0.0, $ts=ts],
	# $addl is not quite right here, but it's close enough.
	["ProFTPD 1.2.5rc1 Server (Debian)"] =
		[$name="ProFTPD", $version=[$major=1,$minor=2,$minor2=5,$addl="rc"], $host=0.0.0.0, $ts=ts],
	["wu-2.4.2-academ[BETA-18-VR14](1)"] = 
		[$name="wu", $version=[$major=2,$minor=4,$minor2=2,$addl="academ"], $host=0.0.0.0, $ts=ts],
	["wu-2.6.2(1)"] =
		[$name="wu", $version=[$major=2,$minor=6,$minor2=2,$addl="1"], $host=0.0.0.0, $ts=ts],
	["Java1.2.2-JDeveloper"] =
		[$name="Java", $version=[$major=1,$minor=2,$minor2=2,$addl="JDeveloper"], $host=0.0.0.0, $ts=ts],
	["Java/1.6.0_13"] = 
		[$name="Java", $version=[$major=1,$minor=6,$minor2=0,$addl="13"], $host=0.0.0.0, $ts=ts],
	# Web Browers are going to have to be pre processed before sending here.  
	# They can't be handled generically by the software framework.
	["Firefox/3.6.7"] =
		[$name="Firefox", $version=[$major=3,$minor=6,$minor2=7], $host=0.0.0.0, $ts=ts],
	["Firefox/4.0b9pre"] = 
		[$name="Firefox", $version=[$major=4,$minor=0, $addl="b9pre"], $host=0.0.0.0, $ts=ts],
	["Python-urllib/3.1"] = 
		[$name="Python-urllib", $version=[$major=3,$minor=1], $host=0.0.0.0, $ts=ts],
	["libwww-perl/5.820"] = 
		[$name="libwww-perl", $version=[$major=5,$minor=820], $host=0.0.0.0, $ts=ts],
	["Wget/1.9+cvs-stable (Red Hat modified)"] = 
		[$name="Wget", $version=[$major=1,$minor=9,$addl="+cvs"], $host=0.0.0.0, $ts=ts],
	["Wget/1.11.4 (Red Hat modified)"] = 
		[$name="Wget", $version=[$major=1,$minor=11,$minor2=4,$addl="Red"], $host=0.0.0.0, $ts=ts],
	# This is currently broken due to the do_split bug.
	#["curl/7.15.1 (i486-pc-linux-gnu) libcurl/7.15.1 OpenSSL/0.9.8a zlib/1.2.3 libidn/0.5.18"] =
	#	[$name="curl", $version=[$major=7,$minor=15,$minor2=1], $host=0.0.0.0, $ts=ts],
	["Apache"] = 
		[$name="Apache", $host=0.0.0.0, $ts=ts],
};

event bro_init()
	{
	for ( sw in matched_software )
		{
		local output = Software::parse(sw, 0.0.0.0, Software::UNKNOWN);
		local sw_test: Software::Info = matched_software[sw];
		if ( sw_test$name == output$name &&
		     Software::cmp_versions(sw_test$version,output$version) == 0 )
			print fmt("success on: %s", sw);
		else
			{
			print fmt("failure on: %s", sw);
			print fmt("    name:    %s", output$name);
			print fmt("    version: %s", output$version);
			}
		}
	}