##! SQL injection detection in HTTP.

@load frameworks/metrics

module HTTP;

export {
	redef enum Notice::Type += {
		SQL_Injection_Attacker,
		SQL_Injection_Attack,
	};
	
	redef enum Metrics::ID += {
		SQL_ATTACKER,
		SQL_ATTACK_AGAINST,
	};

	redef enum Tags += {
		## Indicator of a URI based SQL injection attack.
		URI_SQLI,
		## Indicator of client body based SQL injection attack.  This is 
		## typically the body content of a POST request. Not implemented yet!
		POST_SQLI,
		## Indicator of a cookie based SQL injection attack. Not implemented yet!
		COOKIE_SQLI,
	};

	## This regular expression is used to match URI based SQL injections
	const match_sql_injection_uri = 
		/[\?&][^[:blank:]\|]+?=[\-0-9%]+([[:blank:]]|\/\*.*?\*\/)*['"]?([[:blank:]]|\/\*.*?\*\/|\)?;)+([hH][aA][vV][iI][nN][gG]|[uU][nN][iI][oO][nN]|[eE][xX][eE][cC]|[sS][eE][lL][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[dD][rR][oO][pP]|[dD][eE][cC][lL][aA][rR][eE]|[cC][rR][eE][aA][tT][eE]|[iI][nN][sS][eE][rR][tT])[^a-zA-Z&]/
		| /[\?&][^[:blank:]\|]+?=[\-0-9%]+([[:blank:]]|\/\*.*?\*\/)*['"]?([[:blank:]]|\/\*.*?\*\/|\)?;)+([xX]?[oO][rR]|[aA][nN][dD])([[:blank:]]|\/\*.*?\*\/)+['"]?[^a-zA-Z&]+?=/
		| /[\?&][^[:blank:]]+?=[\-0-9%]*([[:blank:]]|\/\*.*?\*\/)*['"]([[:blank:]]|\/\*.*?\*\/)*(\-|\+|\|\|)([[:blank:]]|\/\*.*?\*\/)*([0-9]|\(?[cC][oO][nN][vV][eE][rR][tT]|[cC][aA][sS][tT])/
		| /[\?&][^[:blank:]\|]+?=([[:blank:]]|\/\*.*?\*\/)*['"]([[:blank:]]|\/\*.*?\*\/|;)*([xX]?[oO][rR]|[aA][nN][dD]|[hH][aA][vV][iI][nN][gG]|[uU][nN][iI][oO][nN]|[eE][xX][eE][cC]|[sS][eE][lL][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[dD][rR][oO][pP]|[dD][eE][cC][lL][aA][rR][eE]|[cC][rR][eE][aA][tT][eE]|[rR][eE][gG][eE][xX][pP]|[iI][nN][sS][eE][rR][tT]|\()[^a-zA-Z&]/
		| /[\?&][^[:blank:]]+?=[^\.]*?([cC][hH][aA][rR]|[aA][sS][cC][iI][iI]|[sS][uU][bB][sS][tT][rR][iI][nN][gG]|[tT][rR][uU][nN][cC][aA][tT][eE]|[vV][eE][rR][sS][iI][oO][nN]|[lL][eE][nN][gG][tT][hH])\(/ &redef;
}

event bro_init()
	{
	Metrics::add_filter(SQL_ATTACKER, [$break_interval=5mins, $note=SQL_Injection_Attack]);
	Metrics::add_filter(SQL_ATTACK_AGAINST, [$break_interval=5mins, $note=SQL_Injection_Attack]);
	}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) &priority=3
	{
	if ( match_sql_injection_uri in unescaped_URI )
		{
		add c$http$tags[URI_SQLI];
		
		Metrics::add_data(SQL_ATTACKER, [$host=c$id$orig_h], 1);
		Metrics::add_data(SQL_ATTACK_AGAINST, [$host=c$id$resp_h], 1);
		}
	}