# @TEST-EXEC: zeek %INPUT
# @TEST-EXEC: btest-diff notice.log

@load frameworks/software/vulnerable

redef Software::asset_tracking = ALL_HOSTS;

global java_1_6_vuln: Software::VulnerableVersionRange = [$max=[$major=1,$minor=6,$minor2=0,$minor3=43]];
global java_1_7_vuln: Software::VulnerableVersionRange = [$min=[$major=1,$minor=7], $max=[$major=1,$minor=7,$minor2=0,$minor3=20]];
redef Software::vulnerable_versions += {
        ["Java"] = set(java_1_6_vuln, java_1_7_vuln)
};

event zeek_init()
	{
	Software::found([$orig_h=1.2.3.4, $orig_p=1234/tcp, $resp_h=4.3.2.1, $resp_p=80/tcp], 
	                [$name="Java", $host=1.2.3.4, $version=[$major=1, $minor=7, $minor2=0, $minor3=15]]);
	Software::found([$orig_h=1.2.3.5, $orig_p=1234/tcp, $resp_h=4.3.2.1, $resp_p=80/tcp], 
	                [$name="Java", $host=1.2.3.5, $version=[$major=1, $minor=6, $minor2=0, $minor3=43]]);
	Software::found([$orig_h=1.2.3.6, $orig_p=1234/tcp, $resp_h=4.3.2.1, $resp_p=80/tcp], 
	                [$name="Java", $host=1.2.3.6, $version=[$major=1, $minor=6, $minor2=0, $minor3=50]]);

	}
