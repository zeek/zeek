##! Detect file downloads that have hash values matching files in Team
##! Cymru's Malware Hash Registry (https://www.team-cymru.com/mhr.html).

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
	option match_file_types = /application\/x-dosexec/ |
	                         /application\/vnd\.ms-cab-compressed/ |
	                         /application\/pdf/ |
	                         /application\/x-shockwave-flash/ |
	                         /application\/x-java-applet/ |
	                         /application\/jar/ |
	                         /video\/mp4/;

	## The Match notice has a sub message with a URL where you can get more
	## information about the file. The %s will be replaced with the SHA-1
	## hash of the file.
	option match_sub_url = "https://www.virustotal.com/gui/search/%s";

	## The malware hash registry runs each malware sample through several
	## A/V engines.  Team Cymru returns a percentage to indicate how
	## many A/V engines flagged the sample as malicious. This threshold
	## allows you to require a minimum detection rate.
	option notice_threshold = 10;
}

function do_mhr_lookup(hash: string, fi: Notice::FileInfo)
	{
	local hash_domain = fmt("%s.malware.hash.cymru.com", hash);

	when [hash, fi, hash_domain] ( local MHR_result = lookup_hostname_txt(hash_domain) )
		{
		# Data is returned as "<dateFirstDetected> <detectionRate>"
		local MHR_answer = split_string1(MHR_result, / /);

		if ( |MHR_answer| == 2 )
			{
			local mhr_detect_rate = to_count(MHR_answer[1]);

			if ( mhr_detect_rate >= notice_threshold )
				{
				local mhr_first_detected = double_to_time(to_double(MHR_answer[0]));
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
	if ( kind == "sha1" && f?$info && f$info?$mime_type &&
	     match_file_types in f$info$mime_type )
		do_mhr_lookup(hash, Notice::create_file_info(f));
	}
