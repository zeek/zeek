// See the file "COPYING" in the main distribution directory for copyright.

/**
 * Wrapper and helper functions for MD5/SHA digest algorithms.
 */

#pragma once

#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include <sys/types.h> // for u_char

#if ( OPENSSL_VERSION_NUMBER < 0x10100000L ) || defined(LIBRESSL_VERSION_NUMBER)
#define EVP_MD_CTX_new EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy

inline void* EVP_MD_CTX_md_data(const EVP_MD_CTX* ctx)
	{
	return ctx->md_data;
	}
#endif

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

EVP_MD_CTX* hash_init(HashAlgorithm alg);

void hash_update(EVP_MD_CTX* c, const void* data, unsigned long len);

void hash_final(EVP_MD_CTX* c, u_char* md);

unsigned char* internal_md5(const unsigned char* data, unsigned long len, unsigned char* out);
