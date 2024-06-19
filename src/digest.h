// See the file "COPYING" in the main distribution directory for copyright.

/**
 * Wrapper and helper functions for MD5/SHA digest algorithms.
 */

#pragma once

#include <sys/types.h> // for u_char
#include <zeek/util.h>
#include <cstdint>
#include <cstdio>

// Required buffer size for an MD5 digest.
#define ZEEK_MD5_DIGEST_LENGTH 16

// Required buffer size for an SHA1 digest.
#define ZEEK_SHA_DIGEST_LENGTH 20

// Required buffer size for an SHA224 digest.
#define ZEEK_SHA224_DIGEST_LENGTH 28

// Required buffer size for an SHA256 digest.
#define ZEEK_SHA256_DIGEST_LENGTH 32

// Required buffer size for an SHA384 digest.
#define ZEEK_SHA384_DIGEST_LENGTH 48

// Required buffer size for an SHA512 digest.
#define ZEEK_SHA512_DIGEST_LENGTH 64

// Buffer size for a digest of any type in hex representation plus size for at
// least a null terminator.
#define ZEEK_DIGEST_PRINT_LENGTH (ZEEK_SHA512_DIGEST_LENGTH * 2) + 1

namespace zeek::detail {

// if you add something here, note that you might have to make sure that the
// static_out member in calculate_digest is still long enough.
enum HashAlgorithm { Hash_MD5, Hash_SHA1, Hash_SHA224, Hash_SHA256, Hash_SHA384, Hash_SHA512 };

inline const char* digest_print(const u_char* digest, size_t n) {
    static char buf[ZEEK_DIGEST_PRINT_LENGTH];
    for ( size_t i = 0; i < n; ++i )
        zeek::util::bytetohex(digest[i], &buf[i * 2]);
    buf[2 * n] = '\0';
    return buf;
}

inline const char* md5_digest_print(const u_char digest[ZEEK_MD5_DIGEST_LENGTH]) {
    return digest_print(digest, ZEEK_MD5_DIGEST_LENGTH);
}

inline const char* sha1_digest_print(const u_char digest[ZEEK_SHA_DIGEST_LENGTH]) {
    return digest_print(digest, ZEEK_SHA_DIGEST_LENGTH);
}

inline const char* sha256_digest_print(const u_char digest[ZEEK_SHA256_DIGEST_LENGTH]) {
    return digest_print(digest, ZEEK_SHA256_DIGEST_LENGTH);
}

struct HashDigestState;

/**
 * Allocates and initializes a new HashDigestState.
 */
HashDigestState* hash_init(HashAlgorithm alg);

/**
 * Adds data to the digest.
 */
void hash_update(HashDigestState* c, const void* data, unsigned long len);

/**
 * Finalizes the digest, writes it to the given buffer and deletes it.
 */
void hash_final(HashDigestState* c, u_char* md);

/**
 * Finalizes the digest and writes it to the given buffer without deleting it afterwards.
 */
void hash_final_no_free(HashDigestState* c, u_char* md);

/**
 * Frees the HashDigestState.
 */
void hash_state_free(HashDigestState* c);

/**
 * Copies the HashDigestState from in to out.
 */
void hash_copy(HashDigestState* out, const HashDigestState* in);

unsigned char* internal_md5(const unsigned char* data, unsigned long len, unsigned char* out);

unsigned char* internal_sha1(const unsigned char* data, unsigned long len, unsigned char* out);

/**
 * Calculates the selected digest.
 * @param Alg Digest algorithm to use.
 * @param data Data to hash.
 * @param len Length of data to hash.
 * @param out Buffer to write data to. If set to nullptr, a static buffer will be used
 * @return Buffer that the hash was written to. Length is dependent on the chosen hash function.
 */
unsigned char* calculate_digest(HashAlgorithm Alg, const unsigned char* data, uint64_t len, unsigned char* out);

} // namespace zeek::detail
