export {
	option max_reassembled_entity_size = 10000 &redef;
}

redef record HTTP::State += {
	entity: string &default="";
};

event http_entity_data(c: connection, is_orig: bool, length: count,
    data: string)
	{
	if ( c?$http_state )
		{
		c$http_state$entity += data;
		}
	}

event http_end_entity(c: connection, is_orig: bool)
	{
	if ( c?$http_state && |c$http_state$entity| > 0 )
		{
		print c$http_state$entity;
		delete c$http_state$entity;
		}
	}
