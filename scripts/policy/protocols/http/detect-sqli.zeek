##! SQL injection attack detection in HTTP.

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
		## Indicator of client body based SQL injection attack.  This is
		## typically the body content of a POST request. Not implemented
		## yet.
		POST_SQLI,
		## Indicator of a cookie based SQL injection attack. Not
		## implemented yet.
		COOKIE_SQLI,
	};

	## Defines the threshold that determines if an SQL injection attack
	## is ongoing based on the number of requests that appear to be SQL
	## injection attacks.
	const sqli_requests_threshold: double = 50.0 &redef;

	## Interval at which to watch for the
	## :zeek:id:`HTTP::sqli_requests_threshold` variable to be crossed.
	## At the end of each interval the counter is reset.
	const sqli_requests_interval = 5min &redef;

	## Collecting samples will add extra data to notice emails
	## by collecting some sample SQL injection url paths.  Disable
	## sample collection by setting this value to 0.
	const collect_SQLi_samples = 5 &redef;

	## Regular expression is used to match URI based SQL injections.
	const match_sql_injection_uri =
		  /[\?&][^[:blank:]\x00-\x1f\|\+]+?=[\-[:alnum:]%]+([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/)*['"]?([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/|\)?;)+.*?([hH][aA][vV][iI][nN][gG]|[uU][nN][iI][oO][nN]|[eE][xX][eE][cC]|[sS][eE][lL][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[dD][rR][oO][pP]|[dD][eE][cC][lL][aA][rR][eE]|[cC][rR][eE][aA][tT][eE]|[iI][nN][sS][eE][rR][tT])([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/)+/
		| /[\?&][^[:blank:]\x00-\x1f\|\+]+?=[\-0-9%]+([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/)*['"]?([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/|\)?;)+([xX]?[oO][rR]|[nN]?[aA][nN][dD])([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/)+['"]?(([^a-zA-Z&]+)?=|[eE][xX][iI][sS][tT][sS])/
		| /[\?&][^[:blank:]\x00-\x1f\+]+?=[\-0-9%]*([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/)*['"]([[:blank:]\x00-\x1f]|\/\*.*?\*\/)*(-|=|\+|\|\|)([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/)*([0-9]|\(?[cC][oO][nN][vV][eE][rR][tT]|[cC][aA][sS][tT])/
		| /[\?&][^[:blank:]\x00-\x1f\|\+]+?=([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/)*['"]([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/|;)*([xX]?[oO][rR]|[nN]?[aA][nN][dD]|[hH][aA][vV][iI][nN][gG]|[uU][nN][iI][oO][nN]|[eE][xX][eE][cC]|[sS][eE][lL][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[dD][rR][oO][pP]|[dD][eE][cC][lL][aA][rR][eE]|[cC][rR][eE][aA][tT][eE]|[rR][eE][gG][eE][xX][pP]|[iI][nN][sS][eE][rR][tT])([[:blank:]\x00-\x1f\+]|\/\*.*?\*\/|[\[(])+[a-zA-Z&]{2,}/
		| /[\?&][^[:blank:]\x00-\x1f\+]+?=[^\.]*?([cC][hH][aA][rR]|[aA][sS][cC][iI][iI]|[sS][uU][bB][sS][tT][rR][iI][nN][gG]|[tT][rR][uU][nN][cC][aA][tT][eE]|[vV][eE][rR][sS][iI][oO][nN]|[lL][eE][nN][gG][tT][hH])\(/
		| /\/\*![[:digit:]]{5}.*?\*\// &redef;

	## A hook that can be used to prevent specific requests from being counted
	## as an injection attempt.  Use a 'break' statement to exit the hook
	## early and ignore the request.
	global HTTP::sqli_policy: hook(c: connection, method: string, unescaped_URI: string);
}

function format_sqli_samples(samples: vector of SumStats::Observation): string
	{
	local ret = "SQL Injection samples\n---------------------";
	for ( i in samples )
		ret += "\n" + samples[i]$str;
	return ret;
	}

event zeek_init() &priority=3
	{
	# Add filters to the metrics so that the metrics framework knows how to
	# determine when it looks like an actual attack and how to respond when
	# thresholds are crossed.
	local r1: SumStats::Reducer = [$stream="http.sqli.attacker", $apply=set(SumStats::SUM, SumStats::SAMPLE), $num_samples=collect_SQLi_samples];
	SumStats::create([$name="detect-sqli-attackers",
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
	                  	NOTICE([$note=SQL_Injection_Attacker,
	                  	        $msg="An SQL injection attacker was discovered!",
	                  	        $email_body_sections=vector(format_sqli_samples(r$samples)),
	                  	        $src=key$host,
	                  	        $identifier=cat(key$host)]);
	                  	}]);

	local r2: SumStats::Reducer = [$stream="http.sqli.victim", $apply=set(SumStats::SUM, SumStats::SAMPLE), $num_samples=collect_SQLi_samples];
	SumStats::create([$name="detect-sqli-victims",
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
	                  	NOTICE([$note=SQL_Injection_Victim,
	                  	        $msg="An SQL injection victim was discovered!",
	                  	        $email_body_sections=vector(format_sqli_samples(r$samples)),
	                  	        $src=key$host,
	                  	        $identifier=cat(key$host)]);
	                  	}]);
	}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) &priority=3
	{
	if ( ! hook HTTP::sqli_policy(c, method, unescaped_URI) )
		return;

	if ( match_sql_injection_uri in unescaped_URI )
		{
		add c$http$tags[URI_SQLI];

		SumStats::observe("http.sqli.attacker", [$host=c$id$orig_h], [$str=original_URI]);
		SumStats::observe("http.sqli.victim",   [$host=c$id$resp_h], [$str=original_URI]);
		}
	}
