##! Detect file downloads over HTTP that have MD5 sums matching files in Team
##! Cymru's Malware Hash Registry (http://www.team-cymru.org/Services/MHR/).
##! By default, not all file transfers will have MD5 sums calculated.  Read the
##! documentation for the :doc:base/protocols/http/file-hash.bro script to see
##! how to configure which transfers will have hashes calculated.

@load base/frameworks/notice
@load base/protocols/http

module HTTP;

export {
	redef enum Notice::Type += {
		## The MD5 sum of a file transferred over HTTP matched in the
		## malware hash registry.
		Malware_Hash_Registry_Match
	};

	## The malware hash registry runs each malware sample through several A/V engines.
	## Team Cymru returns a percentage to indicate how many A/V engines flagged the
	## sample as malicious. This threshold allows you to require a minimum detection
	## rate (default: 50%).
	const MHR_threshold = 50 &redef;
}

event log_http(rec: HTTP::Info)
	{
	if ( rec?$md5 )
		{
		local hash_domain = fmt("%s.malware.hash.cymru.com", rec$md5);
		when ( local MHR_result = lookup_hostname_txt(hash_domain) )
			{
			# Data is returned as "<dateFirstDetected> <detectionRate>"
			local MHR_answer = split1(MHR_result, / /);
			if ( |MHR_answer| == 2 && to_count(MHR_answer[2]) >= MHR_threshold )
				{
				local url = HTTP::build_url_http(rec);
				local message = fmt("%s %s %s", rec$id$orig_h, rec$md5, url);
				NOTICE([$note=Malware_Hash_Registry_Match,
				        $msg=message, $id=rec$id]);
				}
			}
		}
	}
