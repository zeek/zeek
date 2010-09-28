// $Id: SSLCiphers.h 1678 2005-11-08 19:16:37Z vern $

#ifndef SSL_CIPHERS_H
#define SSL_CIPHERS_H

#include "Dict.h"

// --- definitions for sslv3x cipher handling ---------------------------------

/*!
 * In SSLv2, a cipher spec consists of three bytes.
 */
enum SSLv2_CipherSpec {
	// --- standard SSLv2 ciphers
	SSL_CK_RC4_128_WITH_MD5              = 0x010080,
	SSL_CK_RC4_128_EXPORT40_WITH_MD5     = 0x020080,
	SSL_CK_RC2_128_CBC_WITH_MD5          = 0x030080,
	SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5 = 0x040080,
	SSL_CK_IDEA_128_CBC_WITH_MD5         = 0x050080,
	SSL_CK_DES_64_CBC_WITH_MD5           = 0x060040,
	SSL_CK_DES_192_EDE3_CBC_WITH_MD5     = 0x0700C0,
	SSL_CK_RC4_64_WITH_MD5		     = 0x080080
};


/*!
 * In SSLv3x, a cipher spec consists of two bytes.
 */
enum SSL3_1_CipherSpec {
	// --- standard SSLv3x ciphers
	TLS_NULL_WITH_NULL_NULL                = 0x0000,
	TLS_RSA_WITH_NULL_MD5                  = 0x0001,
	TLS_RSA_WITH_NULL_SHA                  = 0x0002,
	TLS_RSA_EXPORT_WITH_RC4_40_MD5         = 0x0003,
	TLS_RSA_WITH_RC4_128_MD5               = 0x0004,
	TLS_RSA_WITH_RC4_128_SHA               = 0x0005,
	TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5     = 0x0006,
	TLS_RSA_WITH_IDEA_CBC_SHA              = 0x0007,
	TLS_RSA_EXPORT_WITH_DES40_CBC_SHA      = 0x0008,
	TLS_RSA_WITH_DES_CBC_SHA               = 0x0009,
	TLS_RSA_WITH_3DES_EDE_CBC_SHA          = 0x000A,
	TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA   = 0x000B,
	TLS_DH_DSS_WITH_DES_CBC_SHA            = 0x000C,
	TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA       = 0x000D,
	TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA   = 0x000E,
	TLS_DH_RSA_WITH_DES_CBC_SHA            = 0x000F,
	TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA       = 0x0010,
	TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA  = 0x0011,
	TLS_DHE_DSS_WITH_DES_CBC_SHA           = 0x0012,
	TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA      = 0x0013,
	TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA  = 0x0014,
	TLS_DHE_RSA_WITH_DES_CBC_SHA           = 0x0015,
	TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA      = 0x0016,
	TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5     = 0x0017,
	TLS_DH_ANON_WITH_RC4_128_MD5           = 0x0018,
	TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA  = 0x0019,
	TLS_DH_ANON_WITH_DES_CBC_SHA           = 0x001A,
	TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA      = 0x001B,
	// --- special SSLv3 ciphers
	SSL_FORTEZZA_KEA_WITH_NULL_SHA         = 0x001C,
	SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA = 0x001D,
	SSL_FORTEZZA_KEA_WITH_RC4_128_SHA      = 0x001E,
	// --- special SSLv3 FIPS ciphers
	SSL_RSA_FIPS_WITH_DES_CBC_SHA		   = 0xFEFE,
	SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA	   = 0XFEFF,
	// --- new 56 bit export ciphers
	TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA     = 0x0062,
	TLS_RSA_EXPORT1024_WITH_RC4_56_SHA      = 0x0064,
	TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA = 0x0063,
	TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA  = 0x0065,
	TLS_DHE_DSS_WITH_RC4_128_SHA            = 0x0066,
	// --- new AES ciphers
	TLS_RSA_WITH_AES_128_CBC_SHA      = 0x002F,
	TLS_DH_DSS_WITH_AES_128_CBC_SHA   = 0x0030,
	TLS_DH_RSA_WITH_AES_128_CBC_SHA   = 0x0031,
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA  = 0x0032,
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA  = 0x0033,
	TLS_DH_ANON_WITH_AES_128_CBC_SHA  = 0x0034,
	TLS_RSA_WITH_AES_256_CBC_SHA      = 0x0035,
	TLS_DH_DSS_WITH_AES_256_CBC_SHA   = 0x0036,
	TLS_DH_RSA_WITH_AES_256_CBC_SHA   = 0x0037,
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA  = 0x0038,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA  = 0x0039,
	TLS_DH_ANON_WITH_AES_256_CBC_SHA  = 0x003A
};

enum SSL_CipherType {
	SSL_CIPHER_TYPE_STREAM,
	SSL_CIPHER_TYPE_BLOCK,
	SSL_CIPHER_TYPE_NULL
};

enum SSL_BulkCipherAlgorithm {
	SSL_CIPHER_NULL,
	SSL_CIPHER_RC4,
	SSL_CIPHER_RC2,
	SSL_CIPHER_DES,
	SSL_CIPHER_3DES,
	SSL_CIPHER_DES40,
	SSL_CIPHER_FORTEZZA,
	SSL_CIPHER_IDEA,
	SSL_CIPHER_AES
};

enum SSL_MACAlgorithm {
	SSL_MAC_NULL,
	SSL_MAC_MD5,
	SSL_MAC_SHA
};

enum SSL_KeyExchangeAlgorithm {
	SSL_KEY_EXCHANGE_NULL,
	SSL_KEY_EXCHANGE_RSA,
	SSL_KEY_EXCHANGE_RSA_EXPORT,
	SSL_KEY_EXCHANGE_DH,
	SSL_KEY_EXCHANGE_DH_DSS,
	SSL_KEY_EXCHANGE_DH_DSS_EXPORT,
	SSL_KEY_EXCHANGE_DH_RSA,
	SSL_KEY_EXCHANGE_DH_RSA_EXPORT,
	SSL_KEY_EXCHANGE_DHE_DSS,
	SSL_KEY_EXCHANGE_DHE_DSS_EXPORT,
	SSL_KEY_EXCHANGE_DHE_RSA,
	SSL_KEY_EXCHANGE_DHE_RSA_EXPORT,
	SSL_KEY_EXCHANGE_DH_ANON,
	SSL_KEY_EXCHANGE_DH_ANON_EXPORT,
	SSL_KEY_EXCHANGE_FORTEZZA_KEA,
	// --- new 56 bit export ciphers
	SSL_KEY_EXCHANGE_RSA_EXPORT1024,
	SSL_KEY_EXCHANGE_DHE_DSS_EXPORT1024
};

#if 0
struct SSL_CipherSpecImprove {
	uint32 identifier;

	// SSL_CipherType cipherType;
	SSL_BulkCipherAlgorithm encryptionAlgorithm;
	SSL_BulkCipherAlgorithm authenticationAlgorithm;
	SSL_BulkCipherAlgorithm keyAlgorithm;
	SSL_MACAlgorithm        macAlgorithm;

	int clearkeySize;
	int encryptedkeySize;
	uint32 flags;	// IsExportable IsSSLv2 IsSSLv30 IsSSLv31
	const char* fullName = "TLS_WITH_NULL_NULL";

};
#endif

struct SSL_CipherSpec {
	uint32 identifier; ///< type code of the CIPHER-SPEC (2 or 3 Bytes)

	SSL_CipherType cipherType;
	uint32 flags;
	SSL_BulkCipherAlgorithm bulkCipherAlgorithm;
	SSL_MACAlgorithm macAlgorithm;
	SSL_KeyExchangeAlgorithm keyExchangeAlgorithm;

	int clearKeySize;     ///< size in bits of plaintext part of master key
	int encryptedKeySize; ///< size in bits of encrypted part of master key
	int hashSize;
};

const uint32 SSL_FLAG_EXPORT = 0x0001; ///< set if exportable cipher
const uint32 SSL_FLAG_SSLv20 = 0x0002; ///< set if cipher defined for SSLv20
const uint32 SSL_FLAG_SSLv30 = 0x0004; ///< set if cipher defined for SSLv30
const uint32 SSL_FLAG_SSLv31 = 0x0008; ///< set if cipher defined for SSLv31

declare(PDict, SSL_CipherSpec);
extern PDict(SSL_CipherSpec) SSL_CipherSpecDict;
extern SSL_CipherSpec SSL_CipherSpecs[];
extern const uint SSL_CipherSpecs_Count;

#endif
