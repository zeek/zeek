enum version {
	SSH1 = 1,
	SSH2 = 2,
	UNK  = 3,
	SSH199 = 4,
};

enum state {
	VERSION_EXCHANGE = 0,
	KEX_INIT         = 1,
	KEX_DH_GEX       = 2,
	KEX_DH           = 3,
	KEX_ECC          = 4,
	KEX_GSS          = 5,
	KEX_RSA          = 6,
	ENCRYPTED        = 7,
};

# diffie-hellman-group1-sha1	[RFC4253]	Section 8.1
# diffie-hellman-group14-sha1	[RFC4253]	Section 8.2
enum KEX_DH_message_id {
	SSH_MSG_KEXDH_INIT  = 30,
	SSH_MSG_KEXDH_REPLY = 31,
};

# diffie-hellman-group-exchange-sha1	[RFC4419]	Section 4.1
# diffie-hellman-group-exchange-sha256	[RFC4419]	Section 4.2
enum KEX_DH_GEX_message_id {
	SSH_MSG_KEX_DH_GEX_REQUEST_OLD = 30,
	SSH_MSG_KEX_DH_GEX_GROUP       = 31,
	SSH_MSG_KEX_DH_GEX_INIT        = 32,
	SSH_MSG_KEX_DH_GEX_REPLY       = 33,
	SSH_MSG_KEX_DH_GEX_REQUEST     = 34,
};

# rsa1024-sha1		[RFC4432]
# rsa2048-sha256	[RFC4432]
enum KEX_RSA_message_id {
	SSH_MSG_KEXRSA_PUBKEY = 30,
	SSH_MSG_KEXRSA_SECRET = 31,
	SSH_MSG_KEXRSA_DONE   = 32,
};

# gss-group1-sha1-*	[RFC4462]	Section 2.3
# gss-group14-sha1-*	[RFC4462]	Section 2.4
# gss-gex-sha1-*	[RFC4462]	Section 2.5
# gss-*			[RFC4462]	Section 2.6
enum KEX_GSS_message_id {
	SSH_MSG_KEXGSS_INIT     = 30,
	SSH_MSG_KEXGSS_CONTINUE = 31,
	SSH_MSG_KEXGSS_COMPLETE = 32,
	SSH_MSG_KEXGSS_HOSTKEY  = 33,
	SSH_MSG_KEXGSS_ERROR    = 34,
	SSH_MSG_KEXGSS_GROUPREQ = 40,
	SSH_MSG_KEXGSS_GROUP    = 41,
};

# ecdh-sha2-*	[RFC5656]
enum KEX_ECDH_message_id {
	SSH_MSG_KEX_ECDH_INIT  = 30,
	SSH_MSG_KEX_ECDH_REPLY = 31,
};

# ecmqv-sha2	[RFC5656]
enum KEX_ECMQV_message_id {
	SSH_MSG_ECMQV_INIT  = 30,
	SSH_MSG_ECMQV_REPLY = 31,
};

enum ssh1_message_id {
	SSH_MSG_NONE                        = 0,
	SSH_MSG_DISCONNECT                  = 1,
	SSH_SMSG_PUBLIC_KEY                 = 2,
	SSH_CMSG_SESSION_KEY                = 3,
	SSH_CMSG_USER                       = 4,
	SSH_CMSG_AUTH_RHOSTS                = 5,
	SSH_CMSG_AUTH_RSA                   = 6,
	SSH_SMSG_AUTH_RSA_CHALLENGE         = 7,
	SSH_CMSG_AUTH_RSA_RESPONSE          = 8,
	SSH_CMSG_AUTH_PASSWORD              = 9,
	SSH_CMSG_REQUEST_PTY                = 10,
	SSH_CMSG_WINDOW_SIZE                = 11,
	SSH_CMSG_EXEC_SHELL                 = 12,
	SSH_CMSG_EXEC_CMD                   = 13,
	SSH_SMSG_SUCCESS                    = 14,
	SSH_SMSG_FAILURE                    = 15,
	SSH_CMSG_STDIN_DATA                 = 16,
	SSH_SMSG_STDOUT_DATA                = 17,
	SSH_SMSG_STDERR_DATA                = 18,
	SSH_CMSG_EOF                        = 19,
	SSH_SMSG_EXITSTATUS                 = 20,
	SSH_MSG_CHANNEL_OPEN_CONFIRMATION   = 21,
	SSH_MSG_CHANNEL_OPEN_FAILURE        = 22,
	SSH_MSG_CHANNEL_DATA                = 23,
	SSH_MSG_CHANNEL_CLOSE               = 24,
	SSH_MSG_CHANNEL_CLOSE_CONFIRMATION  = 25,
	SSH_CMSG_X11_REQUEST_FORWARDING_OLD = 26,
	SSH_SMSG_X11_OPEN                   = 27,
	SSH_CMSG_PORT_FORWARD_REQUEST       = 28,
	SSH_MSG_PORT_OPEN                   = 29,
	SSH_CMSG_AGENT_REQUEST_FORWARDING   = 30,
	SSH_SMSG_AGENT_OPEN                 = 31,
	SSH_MSG_IGNORE                      = 32,
	SSH_CMSG_EXIT_CONFIRMATION          = 33,
	SSH_CMSG_X11_REQUEST_FORWARDING     = 34,
	SSH_CMSG_AUTH_RHOSTS_RSA            = 35,
	SSH_MSG_DEBUG                       = 36,
	SSH_CMSG_REQUEST_COMPRESSION        = 37,
	SSH_CMSG_MAX_PACKET_SIZE            = 38,
	SSH_CMSG_AUTH_TIS                   = 39,
	SSH_SMSG_AUTH_TIS_CHALLENGE         = 40,
	SSH_CMSG_AUTH_TIS_RESPONSE          = 41,
	SSH_CMSG_AUTH_KERBEROS              = 42,
	SSH_SMSG_AUTH_KERBEROS_RESPONSE     = 43,
	SSH_CMSG_HAVE_KERBEROS_TGT          = 44,
};

enum ssh2_message_id {
	MSG_DISCONNECT      = 1,
	MSG_IGNORE          = 2,
	MSG_UNIMPLEMENTED   = 3,
	MSG_DEBUG           = 4,
	MSG_SERVICE_REQUEST = 5,
	MSG_SERVICE_ACCEPT  = 6,
	MSG_KEXINIT         = 20,
	MSG_NEWKEYS         = 21,
};
