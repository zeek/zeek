export {
	option max_reassembled_entity_size = 10000 &redef;
	const http_entity_patterns: vector of pattern = {
		/Will not match!/,
		/<body>/,
		/301 Moved Permanently/,
	} &redef;
}

redef record HTTP::State += {
	entity: string &default="";
};

function num_entity_pattern_matches(state: HTTP::State): count
	{
	local num_matches = 0;
	for ( _, pat in http_entity_patterns )
		{
		if ( pat in state$entity )
			num_matches += 1;
		}

	return num_matches;
	}

event http_entity_data(c: connection, is_orig: bool, length: count,
    data: string)
	{
	if ( c?$http_state )
		{
		local remaining_available = max_reassembled_entity_size - |c$http_state$entity|;
		if ( remaining_available <= 0 )
			return;

		if ( length <= remaining_available )
			c$http_state$entity += data;
		else
			c$http_state$entity += data[:remaining_available];
		}
	}

event http_end_entity(c: connection, is_orig: bool)
	{
	if ( c?$http_state && |c$http_state$entity| > 0 )
		{
		local pat = /Will not match!/;
		print fmt("Did the pattern '%s' match? %s", pat, pat in c$http_state$entity);
		delete c$http_state$entity;
		}
	}
