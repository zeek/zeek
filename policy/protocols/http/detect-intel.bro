##! Intelligence based HTTP detections.

@load intel
@load http/utils

module HTTP;

event log_http(rec: Info)
	{
	local url = HTTP::build_url(rec);
	local query = [$str=url, $subtype="url", $or_tags=set("malicious", "malware")];
	if ( Intel::matcher(query) )
		{
		local msg = fmt("%s accessed a malicious URL from the intelligence framework", rec$id$orig_h);
		NOTICE([$note=Intel::Detection, 
		        $msg=msg, 
		        $sub=HTTP::build_url_http(rec), 
		        $id=rec$id]);
		}
	}