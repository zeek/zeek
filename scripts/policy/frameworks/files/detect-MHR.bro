##! Detect file downloads that have hash values matching files in Team
##! Cymru's Malware Hash Registry (http://www.team-cymru.org/Services/MHR/).

@load base/frameworks/files
@load base/frameworks/notice
@load frameworks/files/hash-all-files

module TeamCymruMalwareHashRegistry;

export {
	redef enum Notice::Type += {
		## The hash value of a file transferred over HTTP matched in the
		## malware hash registry.
		Match
	};

	## File types to attempt matching against the Malware Hash Registry.
	const match_file_types = /application\/x-dosexec/ |
	                         /application\/vnd.ms-cab-compressed/ |
	                         /application\/pdf/ |
	                         /application\/x-shockwave-flash/ |
	                         /application\/x-java-applet/ |
	                         /application\/jar/ |
	                         /video\/mp4/ &redef;

	## The Match notice has a sub message with a URL where you can get more
	## information about the file. The %s will be replaced with the SHA-1
	## hash of the file.
	const match_sub_url = "https://www.virustotal.com/en/search/?query=%s" &redef;

	## The malware hash registry runs each malware sample through several
	## A/V engines.  Team Cymru returns a percentage to indicate how
	## many A/V engines flagged the sample as malicious. This threshold
	## allows you to require a minimum detection rate.
	const notice_threshold = 10 &redef;
}

function do_mhr_lookup(hash: string, fi: Notice::FileInfo)
	{
	local hash_domain = fmt("%s.malware.hash.cymru.com", hash);

	when ( local MHR_result = lookup_hostname_txt(hash_domain) )
		{
		# Data is returned as "<dateFirstDetected> <detectionRate>"
		local MHR_answer = split1(MHR_result, / /);

		if ( |MHR_answer| == 2 )
			{
			local mhr_detect_rate = to_count(MHR_answer[2]);

			if ( mhr_detect_rate >= notice_threshold )
				{
				local mhr_first_detected = double_to_time(to_double(MHR_answer[1]));
				local readable_first_detected = strftime("%Y-%m-%d %H:%M:%S", mhr_first_detected);
				local message = fmt("Malware Hash Registry Detection rate: %d%%  Last seen: %s", mhr_detect_rate, readable_first_detected);
				local virustotal_url = fmt(match_sub_url, hash);
				# We don't have the full fa_file record here in order to
				# avoid the "when" statement cloning it (expensive!).
				local n: Notice::Info = Notice::Info($note=Match, $msg=message, $sub=virustotal_url);
				Notice::populate_file_info2(fi, n);
				NOTICE(n);
				}
			}
		}
	}

event file_hash(f: fa_file, kind: string, hash: string)
	{
	if ( kind == "sha1" && f?$mime_type && match_file_types in f$mime_type )
		do_mhr_lookup(hash, Notice::create_file_info(f));
	}
