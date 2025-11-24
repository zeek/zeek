event http_request(c: connection, method: string, original_URI: string,
    unescaped_URI: string, version: string)
	{
    if ( c?$http && c$http?$uri )
        print fmt("Found HTTP URI %s", c$http$uri);
	}
