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
	#["Firefox/3.6.7"] =
	#	[$name="Firefox", $version=[$major=3,$minor=6,$minor2=7], $host=0.0.0.0, $ts=ts],
	#["Firefox/4.0b9pre"] = 
	#	[$name="Firefox", $version=[$major=4,$minor=0, $addl="b9pre"], $host=0.0.0.0, $ts=ts],
	["Python-urllib/3.1"] = 
		[$name="Python-urllib", $version=[$major=3,$minor=1], $host=0.0.0.0, $ts=ts],
	["libwww-perl/5.820"] = 
		[$name="libwww-perl", $version=[$major=5,$minor=820], $host=0.0.0.0, $ts=ts],
	["Wget/1.9+cvs-stable (Red Hat modified)"] = 
		[$name="Wget", $version=[$major=1,$minor=9,$addl="+cvs"], $host=0.0.0.0, $ts=ts],
	["Wget/1.11.4 (Red Hat modified)"] = 
		[$name="Wget", $version=[$major=1,$minor=11,$minor2=4,$addl="Red Hat modified"], $host=0.0.0.0, $ts=ts],
	# This is currently broken due to the do_split bug.
	#["curl/7.15.1 (i486-pc-linux-gnu) libcurl/7.15.1 OpenSSL/0.9.8a zlib/1.2.3 libidn/0.5.18"] =
	#	[$name="curl", $version=[$major=7,$minor=15,$minor2=1], $host=0.0.0.0, $ts=ts],
	["Apache"] = 
		[$name="Apache", $host=0.0.0.0, $ts=ts],
	["Zope/(Zope 2.7.8-final, python 2.3.5, darwin) ZServer/1.1 Plone/Unknown"] =
		[$name="Zope/(Zope", $version=[$major=2,$minor=7,$minor2=8,$addl="final"], $host=0.0.0.0, $ts=ts],
	["The Bat! (v2.00.9) Personal"] =
		[$name="The Bat!", $version=[$major=2,$minor=0,$minor2=9,$addl="Personal"], $host=0.0.0.0, $ts=ts],
	["Flash/10,2,153,1"] =
		[$name="Flash", $version=[$major=10,$minor=2,$minor2=153,$addl="1"], $host=0.0.0.0, $ts=ts],
	["mt2/1.2.3.967 Oct 13 2010-13:40:24 ord-pixel-x2 pid 0x35a3 13731"] = 
		[$name="mt2", $version=[$major=1,$minor=2,$minor2=3,$addl="967"], $host=0.0.0.0, $ts=ts],
	["CacheFlyServe v26b"] =
		[$name="CacheFlyServe", $version=[$major=26,$addl="b"], $host=0.0.0.0, $ts=ts],
	
	["Apache/2.0.46 (Win32) mod_ssl/2.0.46 OpenSSL/0.9.7b mod_jk2/2.0.4"] =
		[$name="Apache", $version=[$major=2,$minor=0,$minor2=46,$addl="Win32"], $host=0.0.0.0, $ts=ts],
		
	["Apple iPhone v4.3.1 Weather v1.0.0.8G4"] =
		[$name="Apple iPhone", $version=[$major=4,$minor=3,$minor2=1,$addl="Weather"], $host=0.0.0.0, $ts=ts],
	["Mozilla/5.0 (iPhone; U; CPU iPhone OS 4_3_2 like Mac OS X; en-us) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8H7 Safari/6533.18.5"] =
		[$name="Safari", $version=[$major=5,$minor=0,$minor2=2,$addl="Mobile"], $host=0.0.0.0, $ts=ts],
};

event bro_init()
	{
	for ( sw in matched_software )
		{
		local output = Software::parse(sw, 0.0.0.0, Software::UNKNOWN);
		local sw_test: Software::Info;
		sw_test = matched_software[sw];
		if ( sw_test$name == output$name &&
		     Software::cmp_versions(sw_test$version,output$version) == 0 )
			print fmt("success on: %s", sw);
		else
			{
			print fmt("failure on: %s", sw);
			print fmt("    name:    %s", output$name);
			print fmt("    version:  %s", output$version);
			print fmt("    baseline: %s", sw_test$version);
			}
		}
	}