// See the file "COPYING" in the main distribution directory for copyright.

/**
 * Wrapper and helper functions for MD5/SHA digest algorithms.
 */

#ifndef bro_digest_h
#define bro_digest_h

#include <openssl/md5.h>
#include <openssl/sha.h>

#include "Reporter.h"

static inline const char* digest_print(const u_char* digest, size_t n)
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

inline void md5_init(MD5_CTX* c)
	{
	if ( ! MD5_Init(c) )
		reporter->InternalError("MD5_Init failed");
	}

inline void md5_update(MD5_CTX* c, const void* data, unsigned long len)
	{
	if ( ! MD5_Update(c, data, len) )
		reporter->InternalError("MD5_Update failed");
	}

inline void md5_final(MD5_CTX* c, u_char md[MD5_DIGEST_LENGTH])
	{
	if ( ! MD5_Final(md, c) )
		reporter->InternalError("MD5_Final failed");
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
