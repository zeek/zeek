// See the file "COPYING" in the main distribution directory for copyright.

/**
 * Wrapper and helper functions for MD5/SHA digest algorithms.
 */

#ifndef bro_digest_h
#define bro_digest_h

#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define EVP_MD_CTX_new EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy

inline void *EVP_MD_CTX_md_data(const EVP_MD_CTX* ctx)
	{
	return ctx->md_data;
	}
#endif

#include "Reporter.h"

enum HashAlgorithm { Hash_MD5, Hash_SHA1, Hash_SHA224, Hash_SHA256, Hash_SHA384, Hash_SHA512 };

inline const char* digest_print(const u_char* digest, size_t n)
	{
	static char buf[256]; // big enough for any of md5/sha1/sha256
	for ( size_t i = 0; i < n; ++i )
		snprintf(buf + i * 2, 3, "%02x", digest[i]);
	return buf;
	}

inline const char* md5_digest_print(const u_char digest[MD5_DIGEST_LENGTH])
	{
	return digest_print(digest, MD5_DIGEST_LENGTH);
	}

inline const char* sha1_digest_print(const u_char digest[SHA_DIGEST_LENGTH])
	{
	return digest_print(digest, SHA_DIGEST_LENGTH);
	}

inline const char* sha256_digest_print(const u_char digest[SHA256_DIGEST_LENGTH])
	{
	return digest_print(digest, SHA256_DIGEST_LENGTH);
	}

inline EVP_MD_CTX* hash_init(HashAlgorithm alg)
	{
	EVP_MD_CTX *c = EVP_MD_CTX_new();
	/* Allow this to work even if FIPS disables it */
	const EVP_MD* md;
	switch (alg)
		{
		case Hash_MD5:
#ifdef EVP_MD_CTX_FLAG_NON_FIPS_ALLOW
			EVP_MD_CTX_set_flags(c, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
#endif
			md = EVP_md5();
			break;
		case Hash_SHA1:
			md = EVP_sha1();
			break;
		case Hash_SHA224:
			md = EVP_sha224();
			break;
		case Hash_SHA256:
			md = EVP_sha256();
			break;
		case Hash_SHA384:
			md = EVP_sha384();
			break;
		case Hash_SHA512:
			md = EVP_sha512();
			break;
		default:
			reporter->InternalError("Unknown hash algorithm passed to hash_init");
		}
	if ( ! EVP_DigestInit_ex(c, md, NULL) )
		reporter->InternalError("EVP_DigestInit failed");
	return c;
	}

inline void hash_update(EVP_MD_CTX* c, const void* data, unsigned long len)
	{
	if ( ! EVP_DigestUpdate(c, data, len) )
		reporter->InternalError("EVP_DigestUpdate failed");
	}

inline void hash_final(EVP_MD_CTX* c, u_char md[MD5_DIGEST_LENGTH])
	{
	if ( ! EVP_DigestFinal(c, md, NULL) )
		reporter->InternalError("EVP_DigestFinal failed");
	EVP_MD_CTX_free(c);
	}

inline unsigned char* internal_md5(const unsigned char *data, unsigned long len, unsigned char *out)
	{
	static unsigned char static_out[MD5_DIGEST_LENGTH];
	if ( ! out )
		out = static_out; // use static array for return, see OpenSSL man page

	EVP_MD_CTX *c = hash_init(Hash_MD5);
	hash_update(c, data, len);
	hash_final(c, out);
	return out;
	}

#endif //bro_digest_h
