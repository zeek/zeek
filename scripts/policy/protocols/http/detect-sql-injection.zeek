##! SQL injection attack detection in HTTP.
##!
##! The script annotates the notices it generates with an associated $uid
##! connection identifier; always provides an attacker IP address in the
##! $src field; and always provides a victim IP address in the $dst field.

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/protocols/http

module HTTP;

export {
	redef enum Notice::Type += {
		## Indicates that a host performing SQL injection attacks was
		## detected.
		SQL_Injection_Attacker,

		## Indicates that a host was seen to have SQL injection attacks
		## against it.  This is tracked by IP address as opposed to
		## hostname.
		SQL_Injection_Victim,
	};

	redef enum Tags += {
		## Indicator of a URI based SQL injection attack.
		URI_SQLI,
	};

	## Defines the threshold that determines if an SQL injection attack
	## is ongoing based on the number of requests that appear to be SQL
	## injection attacks.
	const sqli_requests_threshold: double = 50.0 &redef;

	## Interval at which to watch for the
	## :zeek:id:`HTTP::sqli_requests_threshold` variable to be crossed.
	## At the end of each interval the counter is reset.
	const sqli_requests_interval = 5 min &redef;

	## Regular expression is used to match URI based SQL injections.
	const match_sql_injection_uri =
		  /[\?&][^[:blank:]\x00-\x1f\|\+]+?=[\-[:alnum:]%]+([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/)*'?([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/|\)?;)+.*?(having|union|exec|select|delete|drop|declare|create|insert)([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/)+/i
		| /[\?&][^[:blank:]\x00-\x1f\|\+]+?=[\-0-9%]+([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/)*'?([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/|\)?;)+(x?or|n?and)([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/)+'?(([^a-zA-Z&]+)?=|exists)/i
		| /[\?&][^[:blank:]\x00-\x1f\+]+?=[\-0-9%]*([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/)*'([[:blank:]\x00-\x1f]|\/\*.*?\*\/)*(-|=|\+|\|\|)([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/)*([0-9]|\(?convert|cast)/i
		| /[\?&][^[:blank:]\x00-\x1f\|\+]+?=([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/)*'([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/|;)*(x?or|n?and|having|union|exec|select|delete|drop|declare|create|regexp|insert)([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/|[\[(])+[a-zA-Z&]{2,}/i
		| /[\?&][^[:blank:]\x00-\x1f\+]+?=[^\.]*?(char|ascii|substring|truncate|version|length)\(/i
		| /\/\*![[:digit:]]{5}.*?\*\// &redef;

	## A hook that can be used to prevent specific requests from being counted
	## as an injection attempt.  Use a 'break' statement to exit the hook
	## early and ignore the request.
	global HTTP::sqli_policy: hook(c: connection, method: string, unescaped_URI: string);
}

redef record SumStats::Observation += {
	uid: string &optional;
};

event zeek_init() &priority=3
	{
	# Add filters to the metrics so that the metrics framework knows how to
	# determine when it looks like an actual attack and how to respond when
	# thresholds are crossed.
	local r1 = SumStats::Reducer(
		$stream="http.sqli.attacker",
		$apply=set(SumStats::SUM, SumStats::SAMPLE),
		$num_samples=1
	);
	local r2 = SumStats::Reducer(
		$stream="http.sqli.victim",
		$apply=set(SumStats::SUM, SumStats::SAMPLE),
		$num_samples=1
	);

	SumStats::create(SumStats::SumStat(
		$name="detect-sqli-attackers",
		$epoch=sqli_requests_interval,
		$reducers=set(r1),
		$threshold_val(key: SumStats::Key, result: SumStats::Result) =
			{
			return result["http.sqli.attacker"]$sum;
			},
		$threshold=sqli_requests_threshold,
		$threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
			{
			local r = result["http.sqli.attacker"];
			local dst = to_addr(r$samples[0]$str);
			local uid = r$samples[0]$uid;
			NOTICE(Notice::Info($note=SQL_Injection_Attacker,
			                    $msg="An SQL injection attacker was discovered!",
			                    $uid=uid,
			                    $src=key$host,
			                    $dst=dst,
			                    $identifier=cat(key$host)));
			}
	));

	SumStats::create(SumStats::SumStat(
		$name="detect-sqli-victims",
		$epoch=sqli_requests_interval,
		$reducers=set(r2),
		$threshold_val(key: SumStats::Key, result: SumStats::Result) =
			{
			return result["http.sqli.victim"]$sum;
			},
		$threshold=sqli_requests_threshold,
		$threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
			{
			local r = result["http.sqli.victim"];
			local src = to_addr(r$samples[0]$str);
			local uid = r$samples[0]$uid;
			NOTICE(Notice::Info($note=SQL_Injection_Victim,
			                    $msg="An SQL injection victim was discovered!",
			                    $uid=uid,
			                    $src=src,
			                    $dst=key$host,
			                    $identifier=cat(key$host)));
			}
	));
	}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) &priority=3
	{
	if ( ! hook HTTP::sqli_policy(c, method, unescaped_URI) )
		return;

	if ( match_sql_injection_uri !in unescaped_URI )
		return;

	add c$http$tags[URI_SQLI];

	local id = c$id;
	local orig = id$orig_h;
	local resp = id$resp_h;
	local uid = c$uid;

	SumStats::observe("http.sqli.attacker", SumStats::Key($host=orig),
		SumStats::Observation($str=fmt("%s", resp), $uid=c$uid));
	SumStats::observe("http.sqli.victim", SumStats::Key($host=resp),
		SumStats::Observation($str=fmt("%s", orig), $uid=c$uid));
	}
