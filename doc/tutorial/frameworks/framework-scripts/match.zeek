@load-sigs ./match.sig

redef record HTTP::Info += {
	num_entity_matches: count &default=0 &log;
};

event signature_match(state: signature_state, msg: string, data: string,
    end_of_match: count)
	{
	if ( state$conn?$http )
		state$conn$http$num_entity_matches += 1;
	}
