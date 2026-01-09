redef record HTTP::State += {
	entity: string &default="";
};

event http_entity_data(c: connection, is_orig: bool, length: count,
    data: string)
	{
	if ( c?$http_state )
		{
		c$http_state$entity += data;
		print c$http_state$entity;
		}
	}
