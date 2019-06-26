# @TEST-EXEC: zeek %INPUT > output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff output

module Software;

global matched_software: table[string] of Software::Description = {
	["OpenSSH_4.4"] = 
		[$name="OpenSSH", $version=[$major=4,$minor=4], $unparsed_version=""],
	["OpenSSH_5.2"] = 
		[$name="OpenSSH", $version=[$major=5,$minor=2], $unparsed_version=""],
	["Apache/2.0.63 (Unix) mod_auth_kerb/5.3 mod_ssl/2.0.63 OpenSSL/0.9.7a mod_fastcgi/2.4.2"] =
		[$name="Apache", $version=[$major=2,$minor=0,$minor2=63,$addl="Unix"], $unparsed_version=""],
	["Apache/1.3.19 (Unix)"] =
		[$name="Apache", $version=[$major=1,$minor=3,$minor2=19,$addl="Unix"], $unparsed_version=""],
	["ProFTPD 1.2.5rc1 Server (Debian)"] =
		[$name="ProFTPD", $version=[$major=1,$minor=2,$minor2=5,$addl="rc1"], $unparsed_version=""],
	["wu-2.4.2-academ[BETA-18-VR14](1)"] = 
		[$name="wu", $version=[$major=2,$minor=4,$minor2=2,$addl="academ"], $unparsed_version=""],
	["wu-2.6.2(1)"] =
		[$name="wu", $version=[$major=2,$minor=6,$minor2=2,$addl="1"], $unparsed_version=""],
	["Java1.2.2-JDeveloper"] =
		[$name="Java", $version=[$major=1,$minor=2,$minor2=2,$addl="JDeveloper"], $unparsed_version=""],
	["Java/1.6.0_13"] = 
		[$name="Java", $version=[$major=1,$minor=6,$minor2=0,$minor3=13], $unparsed_version=""],
	["Python-urllib/3.1"] = 
		[$name="Python-urllib", $version=[$major=3,$minor=1], $unparsed_version=""],
	["libwww-perl/5.820"] = 
		[$name="libwww-perl", $version=[$major=5,$minor=820], $unparsed_version=""],
	["Wget/1.9+cvs-stable (Red Hat modified)"] = 
		[$name="Wget", $version=[$major=1,$minor=9,$addl="+cvs"], $unparsed_version=""],
	["Wget/1.11.4 (Red Hat modified)"] = 
		[$name="Wget", $version=[$major=1,$minor=11,$minor2=4,$addl="Red Hat modified"], $unparsed_version=""],
	["curl/7.15.1 (i486-pc-linux-gnu) libcurl/7.15.1 OpenSSL/0.9.8a zlib/1.2.3 libidn/0.5.18"] =
		[$name="curl", $version=[$major=7,$minor=15,$minor2=1,$addl="i486-pc-linux-gnu"], $unparsed_version=""],
	["Apache"] = 
		[$name="Apache", $unparsed_version=""],
	["Zope/(Zope 2.7.8-final, python 2.3.5, darwin) ZServer/1.1 Plone/Unknown"] =
		[$name="Zope/(Zope", $version=[$major=2,$minor=7,$minor2=8,$addl="final"], $unparsed_version=""],
	["The Bat! (v2.00.9) Personal"] =
		[$name="The Bat!", $version=[$major=2,$minor=0,$minor2=9,$addl="Personal"], $unparsed_version=""],
	["Flash/10,2,153,1"] =
		[$name="Flash", $version=[$major=10,$minor=2,$minor2=153,$minor3=1], $unparsed_version=""],
	# The addl on the following entry isn't so great, but it'll do.
	["Flash%20Player/26.0.0.137 CFNetwork/811.5.4 Darwin/16.6.0 (x86_64)"] =
		[$name="Flash", $version=[$major=26,$minor=0,$minor2=0,$minor3=137,$addl="CFNetwork/811"], $unparsed_version=""],
	["mt2/1.2.3.967 Oct 13 2010-13:40:24 ord-pixel-x2 pid 0x35a3 13731"] = 
		[$name="mt2", $version=[$major=1,$minor=2,$minor2=3,$minor3=967,$addl="Oct"], $unparsed_version=""],
	["CacheFlyServe v26b"] =
		[$name="CacheFlyServe", $version=[$major=26,$addl="b"], $unparsed_version=""],
	["Apache/2.0.46 (Win32) mod_ssl/2.0.46 OpenSSL/0.9.7b mod_jk2/2.0.4"] =
		[$name="Apache", $version=[$major=2,$minor=0,$minor2=46,$addl="Win32"], $unparsed_version=""],
	# I have no clue how I'd support this without a special case.
	#["Apache mod_fcgid/2.3.6 mod_auth_passthrough/2.1 mod_bwlimited/1.4 FrontPage/5.0.2.2635"] =
	#	[$name="Apache", $version=[], $unparsed_version=""],
	["Apple iPhone v4.3.1 Weather v1.0.0.8G4"] =
		[$name="Apple iPhone", $version=[$major=4,$minor=3,$minor2=1,$addl="Weather"], $unparsed_version=""],
	["Mozilla/5.0 (iPhone; U; CPU iPhone OS 4_3_2 like Mac OS X; en-us) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8H7 Safari/6533.18.5"] =
		[$name="Safari", $version=[$major=5,$minor=0,$minor2=2,$addl="Mobile"], $unparsed_version=""],
	["Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16"] = 
		[$name="Chrome", $version=[$major=10,$minor=0,$minor2=648,$minor3=205], $unparsed_version=""],
	["Opera/9.80 (Windows NT 6.1; U; sv) Presto/2.7.62 Version/11.01"] =
		[$name="Opera", $version=[$major=11,$minor=1], $unparsed_version=""],
	["Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.2.11) Gecko/20101013 Lightning/1.0b2 Thunderbird/3.1.5"] =
		[$name="Thunderbird", $version=[$major=3,$minor=1,$minor2=5], $unparsed_version=""],
	["iTunes/9.0 (Macintosh; Intel Mac OS X 10.5.8) AppleWebKit/531.9"] = 
		[$name="iTunes", $version=[$major=9,$minor=0,$addl="Macintosh"], $unparsed_version=""],
	["Java1.3.1_04"] =
		[$name="Java", $version=[$major=1,$minor=3,$minor2=1,$minor3=4], $unparsed_version=""],
	["Mozilla/5.0 (Linux; U; Android 2.3.3; zh-tw; HTC Pyramid Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1"] = 
		[$name="Safari", $version=[$major=4,$minor=0,$addl="Mobile"], $unparsed_version=""],
	["Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_6; en-us) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27"] =
		[$name="Safari", $version=[$major=5,$minor=0,$minor2=4], $unparsed_version=""],
	["Mozilla/5.0 (iPod; U; CPU iPhone OS 4_0 like Mac OS X; en-us) AppleWebKit/532.9 (KHTML, like Gecko) Version/4.0.5 Mobile/8A293 Safari/6531.22.7"] = 
		[$name="Safari", $version=[$major=4,$minor=0,$minor2=5,$addl="Mobile"], $unparsed_version=""],
	["Opera/9.80 (J2ME/MIDP; Opera Mini/9.80 (S60; SymbOS; Opera Mobi/23.348; U; en) Presto/2.5.25 Version/10.54"] = 
		[$name="Opera Mini", $version=[$major=10,$minor=54], $unparsed_version=""],
	["Opera/9.80 (J2ME/MIDP; Opera Mini/5.0.18741/18.794; U; en) Presto/2.4.15"] =
		[$name="Opera Mini", $version=[$major=5,$minor=0,$minor2=18741], $unparsed_version=""],
	["Opera/9.80 (Windows NT 5.1; Opera Mobi/49; U; en) Presto/2.4.18 Version/10.00"] =
		[$name="Opera Mobi", $version=[$major=10,$minor=0], $unparsed_version=""],
	["Mozilla/4.0 (compatible; MSIE 8.0; Android 2.2.2; Linux; Opera Mobi/ADR-1103311355; en) Opera 11.00"] =
		[$name="Opera", $version=[$major=11,$minor=0], $unparsed_version=""],
	["Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.7.2) Gecko/20040804 Netscape/7.2 (ax)"] =
		[$name="Netscape", $version=[$major=7,$minor=2], $unparsed_version=""],
	["Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; GTB5; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506; InfoPath.2)"] =
		[$name="MSIE", $version=[$major=7,$minor=0], $unparsed_version=""],
	["Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; Media Center PC 3.0; .NET CLR 1.0.3705; .NET CLR 1.1.4322; .NET CLR 2.0.50727; InfoPath.1)"] =
		[$name="MSIE", $version=[$major=7,$minor=0,$addl="b"], $unparsed_version=""],
	["Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; Tablet PC 2.0; InfoPath.2; InfoPath.3)"] =
		[$name="MSIE", $version=[$major=8,$minor=0], $unparsed_version=""],
	["Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)"] =
		[$name="MSIE", $version=[$major=9,$minor=0], $unparsed_version=""],
	["Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; InfoPath.3; Creative AutoUpdate v1.40.02)"] =
		[$name="MSIE", $version=[$major=9,$minor=0], $unparsed_version=""],
	["Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)"] =
		[$name="MSIE", $version=[$major=10,$minor=0], $unparsed_version=""],
	# IE 11 normal mode.
	["Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"] =
		[$name="MSIE", $version=[$major=11,$minor=0], $unparsed_version=""],
	# IE 11 compatibility mode
	["Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.3; Trident/7.0; .NET4.0E; .NET4.0C)"] =
		[$name="MSIE", $version=[$major=11,$minor=0], $unparsed_version=""],
	["The Bat! (3.0.1 RC3) Professional"] =
		[$name="The Bat!", $version=[$major=3,$minor=0,$minor2=1,$addl="RC3"], $unparsed_version=""],
	# This is an FTP client (found with CLNT command)
	["Total Commander"] =
		[$name="Total Commander", $version=[], $unparsed_version=""],
	["(vsFTPd 2.0.5)"] =
		[$name="vsFTPd", $version=[$major=2,$minor=0,$minor2=5], $unparsed_version=""],
	["Apple Mail (2.1084)"] = 
		[$name="Apple Mail", $version=[$major=2,$minor=1084], $unparsed_version=""],
	["Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/420+ (KHTML, like Gecko) AdobeAIR/1.0"] = 
		[$name="AdobeAIR", $version=[$major=1,$minor=0], $unparsed_version=""],
	["Mozilla/5.0 (Windows; U; en) AppleWebKit/420+ (KHTML, like Gecko) AdobeAIR/1.0"] = 
		[$name="AdobeAIR", $version=[$major=1,$minor=0], $unparsed_version=""],
	["\\xe6\\xbc\\xab\\xe7\\x94\\xbb\\xe4\\xba\\xba 2.6.2 rv:1.2 (iPhone; iOS 10.3.2; en_US)"] =
		[$name="\xe6\xbc\xab\xe7\x94\xbb\xe4\xba\xba", $version=[$major=2,$minor=6,$minor2=2,$addl="rv:1"], $unparsed_version=""],
	["%E6%9C%89%E9%81%93%E8%AF%8D%E5%85%B8/128 CFNetwork/760.2.6 Darwin/15.3.0 (x86_64)"] =
		[$name="\xe6\x9c\x89\xe9\x81\x93\xe8\xaf\x8d\xe5\x85\xb8", $version=[$major=128,$addl="CFNetwork/760"], $unparsed_version=""],
	["QQ%E9%82%AE%E7%AE%B1/5.3.2.8 CFNetwork/811.5.4 Darwin/16.6.0"] =
		[$name="QQ\xe9\x82\xae\xe7\xae\xb1", $version=[$major=5,$minor=3,$minor2=2,$minor3=8,$addl="CFNetwork/811"], $unparsed_version=""],
	["Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Mobile Safari/537.36 Edge/15.15063"] =
		[$name="Edge", $version=[$major=15,$minor=15063], $unparsed_version=""],
	["A/8.0.0/Google/Pixel#XL/marlin/unknown/QCX3/l8100358318783302904/-/1456904160/-/google/662107/662098/-"] =
		[$name="Android (Google Pixel)", $version=[$major=8,$minor=0,$minor2=0], $unparsed_version=""],
	["A/8.1.0/Google/Pixel#2/walleye/unknown/QCX3/l10660929675510745862/-/104360422/-/google/3606/3607/-"] =
		[$name="Android (Google Pixel)", $version=[$major=8,$minor=1,$minor2=0], $unparsed_version=""],
	["A/9/Google/Pixel#2/walleye/unknown/QCX3/l17463753539612639959/-/2406658516/-/google/724998/724992/-"] =
		[$name="Android (Google Pixel)", $version=[$major=9], $unparsed_version=""],
	["A/9/Google/Pixel#2#XL/taimen/unknown/QCX3/l2640039522761750592/-/1061307257/-/google/1199700/1199701/-"] =
		[$name="Android (Google Pixel)", $version=[$major=9], $unparsed_version=""],
	["A/9/Google/Pixel#2/walleye/unknown/QCX3/l9335055540778241916/-/1576068601/-/google/63672/63666/00:BOOT.XF.1.2.2.c1-00036-M8998LZB-2+01:TZ.BF.4.0.6-00152+03:RPM.BF.1.7-00128+11:MPSS.AT.2.0.c4.5-00253-8998_GEN_PACK-1.172723.1.178350.2+12:ADSP.HT.3.0-00372-CB8998-1+14:VIDEO.VE.4.4-00033+15:SLPI.HB.2.0.c3-00016-M8998AZL-1"] =
		[$name="Android (Google Pixel)", $version=[$major=9], $unparsed_version=""],
};

event zeek_init()
	{
	for ( sw in matched_software )
		{
		local output = Software::parse(sw);
		local baseline = matched_software[sw];
		
		if ( baseline$name == output$name &&
		     sw == output$unparsed_version &&
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
