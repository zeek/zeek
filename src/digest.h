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

inline void md5_init(EVP_MD_CTX** c)
	{
	*c = EVP_MD_CTX_new();
	/* Allow this to work even if FIPS disables it */
#ifdef EVP_MD_CTX_FLAG_NON_FIPS_ALLOW
	EVP_MD_CTX_set_flags(*c, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
#endif
	if ( ! EVP_DigestInit_ex(*c, EVP_md5(), NULL) )
		reporter->InternalError("MD5_Init failed");
	}

inline void md5_update(EVP_MD_CTX* c, const void* data, unsigned long len)
	{
	if ( ! EVP_DigestUpdate(c, data, len) )
		reporter->InternalError("MD5_Update failed");
	}

inline void md5_final(EVP_MD_CTX* c, u_char md[MD5_DIGEST_LENGTH])
	{
	if ( ! EVP_DigestFinal(c, md, NULL) )
		reporter->InternalError("MD5_Final failed");
	}

inline unsigned char* internal_md5(const unsigned char *d, size_t n, unsigned char *md)
	{
		EVP_MD_CTX *c;
		static unsigned char m[MD5_DIGEST_LENGTH];

		if (md == NULL)
			md = m;
		md5_init(&c);
	#ifndef CHARSET_EBCDIC
		md5_update(c, d, n);
	#else
		{
			char temp[1024];
			unsigned long chunk;

			while (n > 0) {
				chunk = (n > sizeof(temp)) ? sizeof(temp) : n;
				ebcdic2ascii(temp, d, chunk);
				md5_update(c, temp, chunk);
				n -= chunk;
				d += chunk;
			}
		}
	#endif
		md5_final(c, md);
		EVP_MD_CTX_free(c);
		return md;
	}

inline void sha1_init(SHA_CTX* c)
	{
	if ( ! SHA1_Init(c) )
		reporter->InternalError("SHA_Init failed");
	}

inline void sha1_update(SHA_CTX* c, const void* data, unsigned long len)
	{
	if ( ! SHA1_Update(c, data, len) )
		reporter->InternalError("SHA_Update failed");
	}

inline void sha1_final(SHA_CTX* c, u_char md[SHA_DIGEST_LENGTH])
	{
	if ( ! SHA1_Final(md, c) )
		reporter->InternalError("SHA_Final failed");
	}

inline void sha256_init(SHA256_CTX* c)
	{
	if ( ! SHA256_Init(c) )
		reporter->InternalError("SHA256_Init failed");
	}

inline void sha256_update(SHA256_CTX* c, const void* data, unsigned long len)
	{
	if ( ! SHA256_Update(c, data, len) )
		reporter->InternalError("SHA256_Update failed");
	}

inline void sha256_final(SHA256_CTX* c, u_char md[SHA256_DIGEST_LENGTH])
	{
	if ( ! SHA256_Final(md, c) )
		reporter->InternalError("SHA256_Final failed");
	}

#endif //bro_digest_h
