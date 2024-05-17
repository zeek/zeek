// See the file "COPYING" in the main distribution directory for copyright.

/**
 * Wrapper and helper functions for MD5/SHA digest algorithms.
 */

#include "zeek/digest.h"

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#include "zeek/Reporter.h"

#if ( OPENSSL_VERSION_NUMBER < 0x10100000L ) || defined(LIBRESSL_VERSION_NUMBER)
#define EVP_MD_CTX_new EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy
#endif

static_assert(ZEEK_MD5_DIGEST_LENGTH == MD5_DIGEST_LENGTH);

static_assert(ZEEK_SHA_DIGEST_LENGTH == SHA_DIGEST_LENGTH);

static_assert(ZEEK_SHA224_DIGEST_LENGTH == SHA224_DIGEST_LENGTH);

static_assert(ZEEK_SHA256_DIGEST_LENGTH == SHA256_DIGEST_LENGTH);

static_assert(ZEEK_SHA384_DIGEST_LENGTH == SHA384_DIGEST_LENGTH);

static_assert(ZEEK_SHA512_DIGEST_LENGTH == SHA512_DIGEST_LENGTH);

namespace zeek::detail {

namespace {
auto* to_native_ptr(HashDigestState* ptr) { return reinterpret_cast<EVP_MD_CTX*>(ptr); }
auto* to_native_ptr(const HashDigestState* ptr) { return reinterpret_cast<const EVP_MD_CTX*>(ptr); }
auto* to_opaque_ptr(EVP_MD_CTX* ptr) { return reinterpret_cast<HashDigestState*>(ptr); }
} // namespace

HashDigestState* hash_init(HashAlgorithm alg) {
    EVP_MD_CTX* c = EVP_MD_CTX_new();
    const EVP_MD* md;

    switch ( alg ) {
        case Hash_MD5:
#ifdef EVP_MD_CTX_FLAG_NON_FIPS_ALLOW
            /* Allow this to work even if FIPS disables it */
            EVP_MD_CTX_set_flags(c, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
#endif
            md = EVP_md5();
            break;
        case Hash_SHA1: md = EVP_sha1(); break;
        case Hash_SHA224: md = EVP_sha224(); break;
        case Hash_SHA256: md = EVP_sha256(); break;
        case Hash_SHA384: md = EVP_sha384(); break;
        case Hash_SHA512: md = EVP_sha512(); break;
        default: reporter->InternalError("Unknown hash algorithm passed to hash_init");
    }

    if ( ! EVP_DigestInit_ex(c, md, NULL) )
        reporter->InternalError("EVP_DigestInit failed");

    return to_opaque_ptr(c);
}

void hash_update(HashDigestState* c, const void* data, unsigned long len) {
    if ( ! EVP_DigestUpdate(to_native_ptr(c), data, len) )
        reporter->InternalError("EVP_DigestUpdate failed");
}

void hash_final(HashDigestState* c, u_char* md) {
    hash_final_no_free(c, md);
    EVP_MD_CTX_free(to_native_ptr(c));
}

void hash_final_no_free(HashDigestState* c, u_char* md) {
    if ( ! EVP_DigestFinal(to_native_ptr(c), md, NULL) )
        reporter->InternalError("EVP_DigestFinal failed");
}

void hash_state_free(HashDigestState* c) {
    if ( c != nullptr )
        EVP_MD_CTX_free(to_native_ptr(c));
}

void hash_copy(HashDigestState* out, const HashDigestState* in) {
    EVP_MD_CTX_copy_ex(to_native_ptr(out), to_native_ptr(in));
}

unsigned char* internal_md5(const unsigned char* data, unsigned long len, unsigned char* out) {
    return calculate_digest(Hash_MD5, data, len, out);
}

unsigned char* internal_sha1(const unsigned char* data, unsigned long len, unsigned char* out) {
    return calculate_digest(Hash_SHA1, data, len, out);
}

unsigned char* calculate_digest(HashAlgorithm alg, const unsigned char* data, uint64_t len, unsigned char* out) {
    // maximum possible length for supported hashes
    static unsigned char static_out[SHA512_DIGEST_LENGTH];

    if ( ! out )
        out = static_out; // use static array for return, see OpenSSL man page

    auto* c = hash_init(alg);
    hash_update(c, data, len);
    hash_final(c, out);
    return out;
}

} // namespace zeek::detail
