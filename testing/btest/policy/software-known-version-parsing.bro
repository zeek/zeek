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
	["ProFTPD 1.2.5rc1 Server (Debian)"] =
		[$name="ProFTPD", $version=[$major=1,$minor=2,$minor2=5,$addl="rc1"], $host=0.0.0.0, $ts=ts],
	["wu-2.4.2-academ[BETA-18-VR14](1)"] = 
		[$name="wu", $version=[$major=2,$minor=4,$minor2=2,$addl="academ"], $host=0.0.0.0, $ts=ts],
	["wu-2.6.2(1)"] =
		[$name="wu", $version=[$major=2,$minor=6,$minor2=2,$addl="1"], $host=0.0.0.0, $ts=ts],
	["Java1.2.2-JDeveloper"] =
		[$name="Java", $version=[$major=1,$minor=2,$minor2=2,$addl="JDeveloper"], $host=0.0.0.0, $ts=ts],
	["Java/1.6.0_13"] = 
		[$name="Java", $version=[$major=1,$minor=6,$minor2=0,$addl="13"], $host=0.0.0.0, $ts=ts],
	["Python-urllib/3.1"] = 
		[$name="Python-urllib", $version=[$major=3,$minor=1], $host=0.0.0.0, $ts=ts],
	["libwww-perl/5.820"] = 
		[$name="libwww-perl", $version=[$major=5,$minor=820], $host=0.0.0.0, $ts=ts],
	["Wget/1.9+cvs-stable (Red Hat modified)"] = 
		[$name="Wget", $version=[$major=1,$minor=9,$addl="+cvs"], $host=0.0.0.0, $ts=ts],
	["Wget/1.11.4 (Red Hat modified)"] = 
		[$name="Wget", $version=[$major=1,$minor=11,$minor2=4,$addl="Red Hat modified"], $host=0.0.0.0, $ts=ts],
	["curl/7.15.1 (i486-pc-linux-gnu) libcurl/7.15.1 OpenSSL/0.9.8a zlib/1.2.3 libidn/0.5.18"] =
		[$name="curl", $version=[$major=7,$minor=15,$minor2=1,$addl="i486-pc-linux-gnu"], $host=0.0.0.0, $ts=ts],
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
	["Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16"] = 
		[$name="Chrome", $version=[$major=10,$minor=0,$minor2=648,$addl="205"], $host=0.0.0.0, $ts=ts],
	["Opera/9.80 (Windows NT 6.1; U; sv) Presto/2.7.62 Version/11.01"] =
		[$name="Opera", $version=[$major=11,$minor=1], $host=0.0.0.0, $ts=ts],
	["Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.11) Gecko/20101013 Lightning/1.0b2 Thunderbird/3.1.5"] =
		[$name="Thunderbird", $version=[$major=3,$minor=1,$minor2=5], $host=0.0.0.0, $ts=ts],
	["iTunes/9.0 (Macintosh; Intel Mac OS X 10.5.8) AppleWebKit/531.9"] = 
		[$name="iTunes", $version=[$major=9,$minor=0,$addl="Macintosh"], $host=0.0.0.0, $ts=ts],
	
};

event bro_init()
	{
	for ( sw in matched_software )
		{
		local output = Software::parse(sw, 0.0.0.0, Software::UNKNOWN);
		local baseline: Software::Info;
		baseline = matched_software[sw];
		if ( baseline$name == output$name &&
		     Software::cmp_versions(baseline$version,output$version) == 0 )
			print fmt("success on: %s", sw);
		else
			{
			print fmt("failure on: %s", sw);
			print fmt("    test name:        %s", output$name);
			print fmt("    test version:     %s", output$version);
			print fmt("    baseline name:    %s", baseline$name);
			print fmt("    baseline version: %s", baseline$version);
			}
		}
	}