# $Id: tm-http.bro,v 1.1.2.1 2005/11/29 21:39:05 sommer Exp $
#
# Requests connections from time-machine for which we have seen a sensitive URI.

@load http
@load time-machine

redef notice_policy += {
	[$pred(a: notice_info) =
		{
		if ( a$note == HTTP::HTTP_SensitiveURI &&
		     a?$conn && ! is_external_connection(a$conn) )
			TimeMachine::request_connection(a$conn, T, "tm-http");
		return F;
		},
	 $result = NOTICE_FILE,	# irrelevant, since we always return F
	 $priority = 1]
};
