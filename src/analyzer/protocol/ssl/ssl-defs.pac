# Some common definitions for the SSL and SSL record-layer analyzers.

%extern{
#include <string>
using std::string;

#include "events.bif.h"
%}

enum ContentType {
	CHANGE_CIPHER_SPEC = 20,
	ALERT = 21,
	HANDSHAKE = 22,
	APPLICATION_DATA = 23,
	V2_ERROR = 300,
	V2_CLIENT_HELLO = 301,
	V2_CLIENT_MASTER_KEY = 302,
	V2_SERVER_HELLO = 304,
	UNKNOWN_OR_V2_ENCRYPTED = 400
};

enum SSLVersions {
	UNKNOWN_VERSION	= 0x0000,
	SSLv20		= 0x0002,
	SSLv30		= 0x0300,
	TLSv10		= 0x0301,
	TLSv11		= 0x0302,
	TLSv12		= 0x0303
};
