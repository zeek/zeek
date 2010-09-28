# $Id:$

# Some common definitions for the SSL and SSL record-layer analyzers.

%extern{
#include <string>
using std::string;
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

%code{
	string* record_type_label(int type)
		{
		switch ( type ) {
		case CHANGE_CIPHER_SPEC:
			return new string("CHANGE_CIPHER_SPEC");
		case ALERT:
			return new string("ALERT");
		case HANDSHAKE:
			return new string("HANDSHAKE");
		case APPLICATION_DATA:
			return new string("APPLICATION_DATA");
		case V2_ERROR:
			return new string("V2_ERROR");
		case V2_CLIENT_HELLO:
			return new string("V2_CLIENT_HELLO");
		case V2_CLIENT_MASTER_KEY:
			return new string("V2_CLIENT_MASTER_KEY");
		case V2_SERVER_HELLO:
			return new string("V2_SERVER_HELLO");
		case UNKNOWN_OR_V2_ENCRYPTED:
			return new string("UNKNOWN_OR_V2_ENCRYPTED");

		default:
			return new string(fmt("UNEXPECTED (%d)", type));
		}
		}
%}

enum SSLVersions {
	UNKNOWN_VERSION	= 0x0000,
	SSLv20		= 0x0002,
	SSLv30		= 0x0300,
	TLSv10		= 0x0301,
	TLSv11		= 0x0302
};
