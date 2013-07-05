##! Detect file downloads that have hash values matching files in Team
##! Cymru's Malware Hash Registry (http://www.team-cymru.org/Services/MHR/).

@load base/frameworks/files
@load base/frameworks/notice
@load frameworks/files/hash-all-files

module MalwareHashRegistery;

export {
	redef enum Notice::Type += {
		## The hash value of a file transferred over HTTP matched in the
		## malware hash registry.
		Match
	};

	redef record Files::Info += {
		## Team Cymru Malware Hash Registry date of first detection.
		mhr_first_detected:  time  &log &optional;
		## Team Cymru Malware Hash Registry percent of detection 
		## among malware scanners.
		mhr_detect_rate:     count &log &optional;
	};

	## File types to attempt matching against the Malware Hash Registry.
	const match_file_types = /^application\/x-dosexec/ &redef;

	## The malware hash registry runs each malware sample through several A/V engines.
	## Team Cymru returns a percentage to indicate how many A/V engines flagged the
	## sample as malicious. This threshold allows you to require a minimum detection
	## rate.
	const notice_threshold = 10 &redef;
}

event file_hash(f: fa_file, kind: string, hash: string)
	{
	if ( kind=="sha1" && match_file_types in f$mime_type )
		{
		local hash_domain = fmt("%s.malware.hash.cymru.com", hash);
		when ( local MHR_result = lookup_hostname_txt(hash_domain) )
			{
			# Data is returned as "<dateFirstDetected> <detectionRate>"
			local MHR_answer = split1(MHR_result, / /);
			if ( |MHR_answer| == 2 )
				{
				f$info$mhr_first_detected = double_to_time(to_double(MHR_answer[1]));
				f$info$mhr_detect_rate = to_count(MHR_answer[2]);

				#print strftime("%Y-%m-%d %H:%M:%S", f$info$mhr_first_detected);
				if ( f$info$mhr_detect_rate >= notice_threshold )
					{
					local url = "";
					# TODO: Create a generic mechanism for creating file "urls".
					#if ( f$source == "HTTP" )
					#	url = HTTP::build_url_http(f);
					local message = fmt("%s %s", hash, url);
					#local message = fmt("Host(s) %s sent a file with SHA1 hash %s to host %s", f$src_host, hash, f$dst_host);
					NOTICE([$note=Match, $msg=message]);
					}
				}
			}
		}
	}
