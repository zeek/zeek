# Defined in RFC 4120
enum KRBMessageTypes {
	AS_REQ    = 10,
	AS_REP    = 11,
	TGS_REQ   = 12,
	TGS_REP   = 13,
	AP_REQ    = 14,
	AP_REP    = 15,
	KRB_SAFE  = 20,
	KRB_PRIV  = 21,
	KRB_CRED  = 22,
	KRB_ERROR = 30,
};

# Defined by IANA in Kerberos Parameters - Pre-authentication and Typed Data
enum KRBPADataTypes {
	PA_TGS_REQ 	 = 1,
	PA_ENC_TIMESTAMP = 2,
	PA_PW_SALT 	 = 3,
	PA_PW_AS_REQ 	 = 16,
	PA_PW_AS_REP	 = 17,
};

# Defined in RFC 4120
enum KRBErrorCodes {
	KDC_ERR_PREAUTH_REQUIRED = 25,
};
