// See the file "COPYING" in the main distribution directory for copyright.
// Copyright (c) 2023, NCC Group / Fox-IT. See COPYING for details.

/*
WARNING: THIS CODE IS NOT SAFE IN MULTI-THREADED ENVIRONMENTS:

* Initializations of static OpenSSL contexts without locking
* Use of SSL contexts is not protected by locks

The involved contexts are EVP_CIPHER_CTX and EVP_PKEY_CTX. These are allocated
lazily and re-used for performance reasons. Previously, every decrypt operation
allocated, initialized and freed these individually, resulting in a significant
performance hit. Given Zeek's single threaded nature, this is fine.
*/

/*
WORK-IN-PROGRESS
Initial working version of decrypting the INITIAL packets from
both client & server to be used by the Spicy parser. Might need a few more
refactors as C++ development is not our main profession.
*/

// Default imports
#include <array>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <vector>

// OpenSSL imports
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>

// Import HILTI
#include <hilti/rt/libhilti.h>

namespace {

// Struct to store decryption info for this specific connection
struct DecryptionInformation {
    std::vector<uint8_t> unprotected_header;
    uint64_t packet_number;
    std::vector<uint8_t> nonce;
    uint8_t packet_number_length;
};

// Return rt::hilti::Bytes::data() value as const uint8_t*
//
// This should be alright: https://stackoverflow.com/a/15172304
inline const uint8_t* data_as_uint8(const hilti::rt::Bytes& b) { return reinterpret_cast<const uint8_t*>(b.data()); }

/*
Constants used by the different functions
*/
const size_t INITIAL_SECRET_LEN = 32;
const size_t AEAD_KEY_LEN = 16;
const size_t AEAD_IV_LEN = 12;
const size_t AEAD_HP_LEN = 16;
const size_t AEAD_SAMPLE_LENGTH = 16;
const size_t AEAD_TAG_LENGTH = 16;
const size_t MAXIMUM_PACKET_NUMBER_LENGTH = 4;

EVP_CIPHER_CTX* get_aes_128_ecb() {
    static EVP_CIPHER_CTX* ctx = nullptr;
    if ( ! ctx ) {
        ctx = EVP_CIPHER_CTX_new();
        EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(), NULL, NULL, NULL, 1);
    }

    return ctx;
}

EVP_CIPHER_CTX* get_aes_128_gcm() {
    static EVP_CIPHER_CTX* ctx = nullptr;
    if ( ! ctx ) {
        ctx = EVP_CIPHER_CTX_new();
        EVP_CipherInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL, 1);
    }

    return ctx;
}

/*
Removes the header protection from the INITIAL packet and returns a DecryptionInformation struct
that is partially filled
*/
DecryptionInformation remove_header_protection(const std::vector<uint8_t>& client_hp, uint64_t encrypted_offset,
                                               const hilti::rt::Bytes& data) {
    DecryptionInformation decryptInfo;
    int outlen;
    auto* ctx = get_aes_128_ecb();
    EVP_CIPHER_CTX_set_key_length(ctx, client_hp.size());
    // Passing an 1 means ENCRYPT
    EVP_CipherInit_ex(ctx, NULL, NULL, client_hp.data(), NULL, 1);

    static_assert(AEAD_SAMPLE_LENGTH > 0);
    assert(data.size() >= encrypted_offset + MAXIMUM_PACKET_NUMBER_LENGTH + AEAD_SAMPLE_LENGTH);

    const uint8_t* sample = data_as_uint8(data) + encrypted_offset + MAXIMUM_PACKET_NUMBER_LENGTH;

    std::array<uint8_t, AEAD_SAMPLE_LENGTH> mask;
    EVP_CipherUpdate(ctx, mask.data(), &outlen, sample, AEAD_SAMPLE_LENGTH);

    // To determine the actual packet number length,
    // we have to remove the mask from the first byte
    uint8_t first_byte = data_as_uint8(data)[0];

    if ( first_byte & 0x80 ) {
        first_byte ^= mask[0] & 0x0F;
    }
    else {
        first_byte ^= first_byte & 0x1F;
    }

    // And now we can fully recover the correct packet number length...
    int recovered_packet_number_length = (first_byte & 0x03) + 1;

    // .. and use this to reconstruct the (partially) unprotected header
    std::vector<uint8_t> unprotected_header(data_as_uint8(data),
                                            data_as_uint8(data) + encrypted_offset + recovered_packet_number_length);

    uint32_t decoded_packet_number = 0;

    unprotected_header[0] = first_byte;
    for ( int i = 0; i < recovered_packet_number_length; ++i ) {
        unprotected_header[encrypted_offset + i] ^= mask[1 + i];
        decoded_packet_number = unprotected_header[encrypted_offset + i] | (decoded_packet_number << 8);
    }

    // Store the information back in the struct
    decryptInfo.packet_number = decoded_packet_number;
    decryptInfo.packet_number_length = recovered_packet_number_length;
    decryptInfo.unprotected_header = std::move(unprotected_header);
    return decryptInfo;
}

/*
Calculate the nonce for the AEAD by XOR'ing the CLIENT_IV and the
decoded packet number, and returns the nonce
*/
std::vector<uint8_t> calculate_nonce(std::vector<uint8_t> client_iv, uint64_t packet_number) {
    for ( int i = 0; i < 8; ++i )
        client_iv[AEAD_IV_LEN - 1 - i] ^= (uint8_t)(packet_number >> 8 * i);

    return client_iv;
}

/*
Function that calls the AEAD decryption routine, and returns the decrypted data.
*/
hilti::rt::Bytes decrypt(const std::vector<uint8_t>& client_key, const hilti::rt::Bytes& data, uint64_t payload_length,
                         const DecryptionInformation& decryptInfo) {
    int out = 0;
    int out2 = 0;

    if ( payload_length < decryptInfo.packet_number_length + AEAD_TAG_LENGTH )
        throw hilti::rt::RuntimeError(hilti::rt::fmt("payload too small %ld < %ld", payload_length,
                                                     decryptInfo.packet_number_length + AEAD_TAG_LENGTH));

    // Bail on large payloads, somewhat arbitrarily. 10k allows for Jumbo frames
    // and sometimes the fuzzer produces packets up to that size as well.
    if ( payload_length > 10000 )
        throw hilti::rt::RuntimeError(hilti::rt::fmt("payload_length too large %ld", payload_length));

    const uint8_t* encrypted_payload = data_as_uint8(data) + decryptInfo.unprotected_header.size();

    int encrypted_payload_size = payload_length - decryptInfo.packet_number_length - AEAD_TAG_LENGTH;

    if ( encrypted_payload_size < 0 )
        throw hilti::rt::RuntimeError(hilti::rt::fmt("encrypted_payload_size underflow %ld", encrypted_payload_size));

    if ( data.size() < decryptInfo.unprotected_header.size() + encrypted_payload_size + AEAD_TAG_LENGTH )
        throw hilti::rt::RuntimeError(hilti::rt::fmt("data too short %ld < %ld", data.size(),
                                                     decryptInfo.unprotected_header.size() + encrypted_payload_size));

    const void* tag_to_check = data.data() + decryptInfo.unprotected_header.size() + encrypted_payload_size;
    int tag_to_check_length = AEAD_TAG_LENGTH;

    // Allocate memory for decryption.
    std::vector<uint8_t> decrypt_buffer(encrypted_payload_size);

    // Setup context
    auto* ctx = get_aes_128_gcm();

    // Set the sizes for the IV and KEY
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, decryptInfo.nonce.size(), NULL);

    EVP_CIPHER_CTX_set_key_length(ctx, client_key.size());

    // Set the KEY and IV
    EVP_CipherInit_ex(ctx, NULL, NULL, client_key.data(), decryptInfo.nonce.data(), 0);

    // Set the tag to be validated after decryption
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag_to_check_length, const_cast<void*>(tag_to_check));

    // Setting the second parameter to NULL will pass it as Associated Data
    EVP_CipherUpdate(ctx, NULL, &out, decryptInfo.unprotected_header.data(), decryptInfo.unprotected_header.size());

    // Set the actual data to decrypt data into the decrypt_buffer. The amount of
    // byte decrypted is stored into `out`
    EVP_CipherUpdate(ctx, decrypt_buffer.data(), &out, encrypted_payload, encrypted_payload_size);

    // Validate whether the decryption was successful or not
    if ( EVP_CipherFinal_ex(ctx, NULL, &out2) == 0 )
        throw hilti::rt::RuntimeError("decryption failed");

    // Copy the decrypted data from the decrypted buffer into a Bytes instance.
    return hilti::rt::Bytes(decrypt_buffer.data(), decrypt_buffer.data() + out);
}


// Pre-initialized SSL contexts for re-use. Not thread-safe. These are only used in expand-only mode
// and have a fixed HKDF info set.
struct HkdfCtx {
    EVP_PKEY_CTX* client_in_ctx = nullptr;
    EVP_PKEY_CTX* server_in_ctx = nullptr;
    EVP_PKEY_CTX* key_info_ctx = nullptr;
    EVP_PKEY_CTX* iv_info_ctx = nullptr;
    EVP_PKEY_CTX* hp_info_ctx = nullptr;
};

struct HkdfCtxParam {
    EVP_PKEY_CTX** ctx;
    std::vector<uint8_t> info;
};

/*
HKDF-Extract as described in https://www.rfc-editor.org/rfc/rfc8446.html#section-7.1
*/
std::vector<uint8_t> hkdf_extract(const std::vector<uint8_t>& salt, const hilti::rt::Bytes& connection_id) {
    std::vector<uint8_t> out_temp(INITIAL_SECRET_LEN);
    size_t initial_secret_len = out_temp.size();
    static EVP_PKEY_CTX* ctx = nullptr;
    if ( ! ctx ) {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
        EVP_PKEY_derive_init(ctx);
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256());
        EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY);
    }

    EVP_PKEY_CTX_set1_hkdf_key(ctx, data_as_uint8(connection_id), connection_id.size());
    EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt.data(), salt.size());
    EVP_PKEY_derive(ctx, out_temp.data(), &initial_secret_len);
    return out_temp;
}

std::vector<uint8_t> hkdf_expand(EVP_PKEY_CTX* ctx, size_t out_len, const std::vector<uint8_t>& key) {
    std::vector<uint8_t> out_temp(out_len);
    EVP_PKEY_CTX_set1_hkdf_key(ctx, key.data(), key.size());
    EVP_PKEY_derive(ctx, out_temp.data(), &out_len);
    return out_temp;
}

class QuicPacketProtection {
public:
    std::vector<uint8_t> GetSecret(bool is_orig, uint32_t version, const hilti::rt::Bytes& connection_id) {
        const auto& ctxs = GetHkdfCtxs();
        const auto initial_secret = hkdf_extract(GetInitialSalt(version), connection_id);
        EVP_PKEY_CTX* ctx = is_orig ? ctxs.client_in_ctx : ctxs.server_in_ctx;
        return hkdf_expand(ctx, INITIAL_SECRET_LEN, initial_secret);
    }

    std::vector<uint8_t> GetKey(const std::vector<uint8_t>& secret) {
        const auto& ctxs = GetHkdfCtxs();
        return hkdf_expand(ctxs.key_info_ctx, AEAD_KEY_LEN, secret);
    }

    std::vector<uint8_t> GetIv(const std::vector<uint8_t>& secret) {
        const auto& ctxs = GetHkdfCtxs();
        return hkdf_expand(ctxs.iv_info_ctx, AEAD_IV_LEN, secret);
    }

    std::vector<uint8_t> GetHp(const std::vector<uint8_t>& secret) {
        const auto& ctxs = GetHkdfCtxs();
        return hkdf_expand(ctxs.hp_info_ctx, AEAD_HP_LEN, secret);
    }

    virtual bool Supports(uint32_t version) const = 0;
    virtual const std::vector<uint8_t>& GetInitialSalt(uint32_t version) const = 0;
    virtual HkdfCtx& GetHkdfCtxs() = 0;

    virtual ~QuicPacketProtection() = default;

    // Helper to initialize HKDF expand only contexts.
    static void Initialize(std::vector<HkdfCtxParam>& params) {
        for ( const auto& p : params ) {
            *p.ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
            EVP_PKEY_derive_init(*p.ctx);
            EVP_PKEY_CTX_set_hkdf_md(*p.ctx, EVP_sha256());
            EVP_PKEY_CTX_hkdf_mode(*p.ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY);
            EVP_PKEY_CTX_add1_hkdf_info(*p.ctx, p.info.data(), p.info.size());
        }
    }
};

// QUIC v1
//
// https://datatracker.ietf.org/doc/html/rfc9001
class QuicPacketProtectionV1 : public QuicPacketProtection {
public:
    virtual bool Supports(uint32_t version) const override {
        // Quic V1
        if ( version == 0x00000001 )
            return true;

        // Draft 22 through 34
        if ( version >= 0xff000016 && version <= 0xff000022 )
            return true;

        // mvfst from facebook
        if ( version == 0xfaceb001 || (version >= 0xfaceb002 && version <= 0xfaceb013) )
            return true;

        return false;
    };

    virtual const std::vector<uint8_t>& GetInitialSalt(uint32_t version) const override {
        static std::vector<uint8_t> INITIAL_SALT_V1 = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
                                                       0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};

        // https://insights.sei.cmu.edu/documents/4499/2023_017_001_890985.pdf
        static std::vector<uint8_t> INITIAL_SALT_D22 = {0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0xe9, 0x19, 0x3a,
                                                        0x96, 0xcd, 0x21, 0x51, 0x9e, 0xbd, 0x7a, 0x02, 0x64, 0x4a};

        static std::vector<uint8_t> INITIAL_SALT_D23_D28 = {0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7,
                                                            0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02};

        static std::vector<uint8_t> INITIAL_SALT_D29_D32 = {0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
                                                            0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99};
        if ( version == 0xff000016 )
            return INITIAL_SALT_D22;

        if ( version >= 0xff000017 && version <= 0xff00001c )
            return INITIAL_SALT_D23_D28;

        if ( version >= 0xff00001d && version <= 0xff000020 )
            return INITIAL_SALT_D29_D32;

        if ( version == 0xfaceb001 )
            return INITIAL_SALT_D22;

        if ( version >= 0xfaceb002 && version <= 0xfaceb013 )
            return INITIAL_SALT_D23_D28;

        return INITIAL_SALT_V1;
    }

    virtual HkdfCtx& GetHkdfCtxs() override { return hkdf_ctxs; }

    // Pre-initialize SSL context for reuse with HKDF info set to version specific values.
    static void Initialize() {
        std::vector<uint8_t> CLIENT_INITIAL_INFO = {0x00, 0x20, 0x0f, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x63,
                                                    0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x69, 0x6e, 0x00};

        std::vector<uint8_t> SERVER_INITIAL_INFO = {0x00, 0x20, 0x0f, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x73,
                                                    0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x69, 0x6e, 0x00};

        std::vector<uint8_t> KEY_INFO = {0x00, 0x10, 0x0e, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20,
                                         0x71, 0x75, 0x69, 0x63, 0x20, 0x6b, 0x65, 0x79, 0x00};

        std::vector<uint8_t> IV_INFO = {0x00, 0x0c, 0x0d, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20,
                                        0x71, 0x75, 0x69, 0x63, 0x20, 0x69, 0x76, 0x00};

        std::vector<uint8_t> HP_INFO = {0x00, 0x10, 0x0d, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20,
                                        0x71, 0x75, 0x69, 0x63, 0x20, 0x68, 0x70, 0x00};

        std::vector<HkdfCtxParam> hkdf_ctx_params = {
            {&hkdf_ctxs.client_in_ctx, std::move(CLIENT_INITIAL_INFO)},
            {&hkdf_ctxs.server_in_ctx, std::move(SERVER_INITIAL_INFO)},
            {&hkdf_ctxs.key_info_ctx, std::move(KEY_INFO)},
            {&hkdf_ctxs.iv_info_ctx, std::move(IV_INFO)},
            {&hkdf_ctxs.hp_info_ctx, std::move(HP_INFO)},
        };

        QuicPacketProtection::Initialize(hkdf_ctx_params);

        instance = std::make_unique<QuicPacketProtectionV1>();
    }

    static HkdfCtx hkdf_ctxs;
    static std::unique_ptr<QuicPacketProtectionV1> instance;
};

HkdfCtx QuicPacketProtectionV1::hkdf_ctxs = {0};
std::unique_ptr<QuicPacketProtectionV1> QuicPacketProtectionV1::instance = nullptr;


// QUIC v2
//
// https://datatracker.ietf.org/doc/rfc9369/
class QuicPacketProtectionV2 : public QuicPacketProtection {
public:
    virtual bool Supports(uint32_t version) const override { return version == 0x6b3343cf; }

    virtual const std::vector<uint8_t>& GetInitialSalt(uint32_t version) const override {
        static std::vector<uint8_t> INITIAL_SALT_V2 = {0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
                                                       0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9};

        return INITIAL_SALT_V2;
    }

    virtual HkdfCtx& GetHkdfCtxs() override { return hkdf_ctxs; }

    static void Initialize() {
        std::vector<uint8_t> CLIENT_INITIAL_INFO_V2 = {0x00, 0x20, 0x0f, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x63,
                                                       0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x69, 0x6e, 0x00};

        std::vector<uint8_t> SERVER_INITIAL_INFO_V2 = {0x00, 0x20, 0x0f, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x73,
                                                       0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x69, 0x6e, 0x00};

        std::vector<uint8_t> KEY_INFO_V2 = {0x00, 0x10, 0x10, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x71,
                                            0x75, 0x69, 0x63, 0x76, 0x32, 0x20, 0x6b, 0x65, 0x79, 0x00};

        std::vector<uint8_t> IV_INFO_V2 = {0x00, 0x0c, 0x0f, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x71,
                                           0x75, 0x69, 0x63, 0x76, 0x32, 0x20, 0x69, 0x76, 0x00};

        std::vector<uint8_t> HP_INFO_V2 = {0x00, 0x10, 0x0f, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x71,
                                           0x75, 0x69, 0x63, 0x76, 0x32, 0x20, 0x68, 0x70, 0x00};

        std::vector<HkdfCtxParam> hkdf_ctx_params = {
            {&hkdf_ctxs.client_in_ctx, std::move(CLIENT_INITIAL_INFO_V2)},
            {&hkdf_ctxs.server_in_ctx, std::move(SERVER_INITIAL_INFO_V2)},
            {&hkdf_ctxs.key_info_ctx, std::move(KEY_INFO_V2)},
            {&hkdf_ctxs.iv_info_ctx, std::move(IV_INFO_V2)},
            {&hkdf_ctxs.hp_info_ctx, std::move(HP_INFO_V2)},
        };

        QuicPacketProtection::Initialize(hkdf_ctx_params);
        instance = std::make_unique<QuicPacketProtectionV2>();
    }

    static HkdfCtx hkdf_ctxs;
    static std::unique_ptr<QuicPacketProtectionV2> instance;
};

HkdfCtx QuicPacketProtectionV2::hkdf_ctxs = {0};
std::unique_ptr<QuicPacketProtectionV2> QuicPacketProtectionV2::instance = nullptr;

} // namespace

/*
Function that is called from Spicy, decrypting an INITIAL packet and returning
the decrypted payload back to the analyzer.
*/
hilti::rt::Bytes QUIC_decrypt_crypto_payload(const hilti::rt::integer::safe<uint32_t>& version,
                                             const hilti::rt::Bytes& data, const hilti::rt::Bytes& connection_id,
                                             const hilti::rt::integer::safe<uint64_t>& encrypted_offset,
                                             const hilti::rt::integer::safe<uint64_t>& payload_length,
                                             const hilti::rt::Bool& from_client) {
    static bool initialized = false;
    if ( ! initialized ) {
        QuicPacketProtectionV1::Initialize();
        QuicPacketProtectionV2::Initialize();
        initialized = true;
    }

    if ( payload_length < 20 )
        throw hilti::rt::RuntimeError(hilti::rt::fmt("payload too small %ld < 20", payload_length));

    if ( (data.size() < encrypted_offset + payload_length) )
        throw hilti::rt::RuntimeError(
            hilti::rt::fmt("packet too small %ld %ld", data.size(), encrypted_offset + payload_length));

    uint32_t v = version;
    QuicPacketProtection* qpp = nullptr;

    if ( QuicPacketProtectionV1::instance->Supports(v) ) {
        qpp = QuicPacketProtectionV1::instance.get();
    }
    else if ( QuicPacketProtectionV2::instance->Supports(v) ) {
        qpp = QuicPacketProtectionV2::instance.get();
    }
    else {
        throw hilti::rt::RuntimeError(hilti::rt::fmt("unable to decrypt QUIC version 0x%lx", version));
    }

    const auto& secret = qpp->GetSecret(from_client, v, connection_id);
    std::vector<uint8_t> key = qpp->GetKey(secret);
    std::vector<uint8_t> iv = qpp->GetIv(secret);
    std::vector<uint8_t> hp = qpp->GetHp(secret);

    DecryptionInformation decryptInfo = remove_header_protection(hp, encrypted_offset, data);

    // Calculate the correct nonce for the decryption
    decryptInfo.nonce = calculate_nonce(std::move(iv), decryptInfo.packet_number);

    return decrypt(key, data, payload_length, decryptInfo);
}
