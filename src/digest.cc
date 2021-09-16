// See the file "COPYING" in the main distribution directory for copyright.

/**
 * Wrapper and helper functions for MD5/SHA digest algorithms.
 */

#include "zeek/digest.h"

#include "zeek/Reporter.h"

namespace zeek::detail
	{

EVP_MD_CTX* hash_init(HashAlgorithm alg)
	{
	EVP_MD_CTX* c = EVP_MD_CTX_new();
	const EVP_MD* md;

	switch ( alg )
		{
		case Hash_MD5:
#ifdef EVP_MD_CTX_FLAG_NON_FIPS_ALLOW
			/* Allow this to work even if FIPS disables it */
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

void hash_update(EVP_MD_CTX* c, const void* data, unsigned long len)
	{
	if ( ! EVP_DigestUpdate(c, data, len) )
		reporter->InternalError("EVP_DigestUpdate failed");
	}

void hash_final(EVP_MD_CTX* c, u_char* md)
	{
	if ( ! EVP_DigestFinal(c, md, NULL) )
		reporter->InternalError("EVP_DigestFinal failed");

	EVP_MD_CTX_free(c);
	}

unsigned char* internal_md5(const unsigned char* data, unsigned long len, unsigned char* out)
	{
	return calculate_digest(Hash_MD5, data, len, out);
	}

unsigned char* calculate_digest(HashAlgorithm alg, const unsigned char* data, uint64_t len,
                                unsigned char* out)
	{
	// maximum possible length for supported hashes
	static unsigned char static_out[SHA512_DIGEST_LENGTH];

	if ( ! out )
		out = static_out; // use static array for return, see OpenSSL man page

	EVP_MD_CTX* c = hash_init(alg);
	hash_update(c, data, len);
	hash_final(c, out);
	return out;
	}

	} // namespace zeek::detail
