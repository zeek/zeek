// See the file "COPYING" in the main distribution directory for copyright.

/*
WORK-IN-PROGRESS
Initial working version of decrypting the INITIAL packets from
both client & server to be used by the Spicy parser. Might need a few more
refactors as C++ development is not our main profession.
*/

// Default imports
#include <stdlib.h>
#include <cstring>
#include <vector>
#include <iostream>
#include <string>

// OpenSSL imports
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

// Import HILTI
#include <hilti/rt/libhilti.h>

// Struct to store decryption info for this specific connection
struct DecryptionInformation
{
    std::vector<uint8_t> unprotected_header;
    std::vector<uint8_t> protected_header;
    uint64_t packet_number;
    std::vector<uint8_t> nonce;
    uint8_t packet_number_length;
};

/*
Constants used in the HKDF functions. HKDF-Expand-Label uses labels
such as 'quic key' and 'quic hp'. These labels can obviously be
calculated dynamically, but are incluced statically for now, as the
goal of this analyser is only to analyze the INITIAL packets.
*/

std::vector<uint8_t> INITIAL_SALT_V1 = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5,
    0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
    0xad, 0xcc, 0xbb, 0x7f, 0x0a};

std::vector<uint8_t> CLIENT_INITIAL_INFO = {
    0x00, 0x20, 0x0f, 0x74, 0x6c,
    0x73, 0x31, 0x33, 0x20, 0x63,
    0x6c, 0x69, 0x65, 0x6e, 0x74,
    0x20, 0x69, 0x6e, 0x00};

std::vector<uint8_t> SERVER_INITIAL_INFO = {
    0x00, 0x20, 0x0f, 0x74, 0x6c,
    0x73, 0x31, 0x33, 0x20, 0x73,
    0x65, 0x72, 0x76, 0x65, 0x72,
    0x20, 0x69, 0x6e, 0x00};

std::vector<uint8_t> KEY_INFO = {
    0x00, 0x10, 0x0e, 0x74, 0x6c,
    0x73, 0x31, 0x33, 0x20, 0x71,
    0x75, 0x69, 0x63, 0x20, 0x6b,
    0x65, 0x79, 0x00};

std::vector<uint8_t> IV_INFO = {
    0x00, 0x0c, 0x0d, 0x74, 0x6c,
    0x73, 0x31, 0x33, 0x20, 0x71,
    0x75, 0x69, 0x63, 0x20, 0x69,
    0x76, 0x00};

std::vector<uint8_t> HP_INFO = {
    0x00, 0x10, 0x0d, 0x74, 0x6c,
    0x73, 0x31, 0x33, 0x20, 0x71,
    0x75, 0x69, 0x63, 0x20, 0x68,
    0x70, 0x00};

/*
Constants used by the different functions
*/
const size_t INITIAL_SECRET_LEN = 32;
const size_t AEAD_KEY_LEN = 16;
const size_t AEAD_IV_LEN = 12;
const size_t AEAD_HP_LEN = 16;
const size_t AEAD_SAMPLE_LENGTH = 16;
const size_t AEAD_TAG_LENGTH = 16;
const size_t MAXIMUM_PACKET_LENGTH = 1500;
const size_t MAXIMUM_PACKET_NUMBER_LENGTH = 4;

/*
HKDF-Extract as decribed in https://www.rfc-editor.org/rfc/rfc8446.html#section-7.1
*/
std::vector<uint8_t> hkdf_extract(std::vector<uint8_t> connection_id)
{
    std::vector<uint8_t> out_temp(INITIAL_SECRET_LEN);
    size_t initial_secret_len = out_temp.size();
    const EVP_MD *digest = EVP_sha256();
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    EVP_PKEY_derive_init(pctx);
    EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY);
    EVP_PKEY_CTX_set_hkdf_md(pctx, digest);
    EVP_PKEY_CTX_set1_hkdf_key(pctx,
                               connection_id.data(),
                               connection_id.size());
    EVP_PKEY_CTX_set1_hkdf_salt(pctx,
                                INITIAL_SALT_V1.data(),
                                INITIAL_SALT_V1.size());
    EVP_PKEY_derive(pctx,
                    out_temp.data(),
                    reinterpret_cast<size_t *>(&initial_secret_len));
    EVP_PKEY_CTX_free(pctx);
    return out_temp;
}

/*
HKDF-Expand-Label as decribed in https://www.rfc-editor.org/rfc/rfc8446.html#section-7.1
that uses the global constant labels such as 'quic hp'.
*/
std::vector<uint8_t> hkdf_expand(size_t out_len,
                                 std::vector<uint8_t> key,
                                 std::vector<uint8_t> info)
{
    std::vector<uint8_t> out_temp(out_len);
    const EVP_MD *digest = EVP_sha256();
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    EVP_PKEY_derive_init(pctx);
    EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY);
    EVP_PKEY_CTX_set_hkdf_md(pctx, digest);
    EVP_PKEY_CTX_set1_hkdf_key(pctx, key.data(), key.size());
    EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), info.size());
    EVP_PKEY_derive(pctx, out_temp.data(), &out_len);
    EVP_PKEY_CTX_free(pctx);
    return out_temp;
}

/*
Removes the header protection from the INITIAL packet and returns a DecryptionInformation struct that is partially filled
*/
DecryptionInformation remove_header_protection(std::vector<uint8_t> client_hp, uint8_t encrypted_offset, std::vector<uint8_t> encrypted_packet)
{
    DecryptionInformation decryptInfo;
    int outlen;
    auto cipher = EVP_aes_128_ecb();
    auto ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, 1);
    EVP_CIPHER_CTX_set_key_length(ctx, client_hp.size());
    // Passing an 1 means ENCRYPT
    EVP_CipherInit_ex(ctx, NULL, NULL, client_hp.data(), NULL, 1);

    std::vector<uint8_t> sample(encrypted_packet.begin() +
                                    encrypted_offset +
                                    MAXIMUM_PACKET_NUMBER_LENGTH,

                                encrypted_packet.begin() +
                                    encrypted_offset +
                                    MAXIMUM_PACKET_NUMBER_LENGTH +
                                    AEAD_SAMPLE_LENGTH);
    std::vector<uint8_t> mask(sample.size());
    EVP_CipherUpdate(ctx, mask.data(), &outlen, sample.data(), AEAD_SAMPLE_LENGTH);

    // To determine the actual packet number length,
    // we have to remove the mask from the first byte
    uint8_t first_byte = encrypted_packet[0];

    if (first_byte & 0x80)
    {
        first_byte ^= mask[0] & 0x0F;
    }
    else
    {
        first_byte ^= first_byte & 0x1F;
    }

    // And now we can fully recover the correct packet number length...
    int recovered_packet_number_length = (first_byte & 0x03) + 1;

    // .. and use this to reconstruct the (partially) unprotected header
    std::vector<uint8_t> unprotected_header(
        encrypted_packet.begin(),

        encrypted_packet.begin() +
            encrypted_offset +
            recovered_packet_number_length);

    uint32_t decoded_packet_number = 0;

    unprotected_header[0] = first_byte;
    for (int i = 0; i < recovered_packet_number_length; ++i)
    {
        unprotected_header[encrypted_offset + i] ^= mask[1 + i];
        decoded_packet_number =
            unprotected_header[encrypted_offset + i] |
            (decoded_packet_number << 8);
    }
    std::vector<uint8_t> protected_header(encrypted_packet.begin(),
                                          encrypted_packet.begin() +
                                              encrypted_offset +
                                              recovered_packet_number_length);

    // Store the information back in the struct
    decryptInfo.packet_number = decoded_packet_number;
    decryptInfo.packet_number_length = recovered_packet_number_length;
    decryptInfo.protected_header = protected_header;
    decryptInfo.unprotected_header = unprotected_header;
    return decryptInfo;
}

/*
Calculate the nonce for the AEAD by XOR'ing the CLIENT_IV and the
decoded packet number, and returns the nonce
*/
std::vector<uint8_t> calculate_nonce(std::vector<uint8_t> client_iv, uint64_t packet_number)
{
    std::vector<uint8_t> nonce = client_iv;

    for (int i = 0; i < 8; ++i)
    {
        nonce[AEAD_IV_LEN - 1 - i] ^=
            (uint8_t)(packet_number >> 8 * i);
    }

    // Return the nonce
    return nonce;
}

/*
Function that calls the AEAD decryption routine, and returns the
decrypted data
*/
std::vector<uint8_t> decrypt(std::vector<uint8_t> client_key,
                             std::vector<uint8_t> encrypted_packet,
                             uint64_t payload_offset,
                             DecryptionInformation decryptInfo)
{
    int out, out2, res;
    std::vector<uint8_t> encrypted_payload(
        encrypted_packet.begin() +
            decryptInfo.protected_header.size(),

        encrypted_packet.begin() +
            decryptInfo.protected_header.size() +
            payload_offset -
            decryptInfo.packet_number_length -
            AEAD_TAG_LENGTH);

    std::vector<uint8_t> tag_to_check(
        encrypted_packet.begin() +
            decryptInfo.protected_header.size() +
            payload_offset -
            decryptInfo.packet_number_length -
            AEAD_TAG_LENGTH,

        encrypted_packet.begin() +
            decryptInfo.protected_header.size() +
            payload_offset -
            decryptInfo.packet_number_length);

    unsigned char decrypt_buffer[MAXIMUM_PACKET_LENGTH];

    // Setup context
    auto cipher = EVP_aes_128_gcm();
    auto ctx = EVP_CIPHER_CTX_new();

    EVP_CipherInit_ex(ctx,
                      cipher,
                      NULL,
                      NULL,
                      NULL,
                      0);

    // Set the sizes for the IV and KEY
    EVP_CIPHER_CTX_ctrl(ctx,
                        EVP_CTRL_CCM_SET_IVLEN,
                        decryptInfo.nonce.size(),
                        NULL);

    EVP_CIPHER_CTX_set_key_length(ctx,
                                  client_key.size());

    // Set the KEY and IV
    EVP_CipherInit_ex(ctx,
                      NULL,
                      NULL,
                      client_key.data(),
                      decryptInfo.nonce.data(),
                      0);

    // Set the tag to be validated after decryption
    EVP_CIPHER_CTX_ctrl(ctx,
                        EVP_CTRL_CCM_SET_TAG,
                        tag_to_check.size(),
                        tag_to_check.data());

    // Setting the second parameter to NULL will pass it as Associated Data
    EVP_CipherUpdate(ctx,
                     NULL,
                     &out,
                     decryptInfo.unprotected_header.data(),
                     decryptInfo.unprotected_header.size());

    // Set the actual data to decrypt data into the decrypt_buffer. The amount of
    // byte decrypted is stored into `out`
    EVP_CipherUpdate(ctx,
                     decrypt_buffer,
                     &out,
                     encrypted_payload.data(),
                     encrypted_payload.size());

    // Validate whether the decryption was successful or not
    EVP_CipherFinal_ex(ctx, NULL, &out2);

    // Copy the decrypted data from the decrypted buffer into a new vector and return this
    // Use the `out` variable to only include relevant bytes
    std::vector<uint8_t> decrypted_data(decrypt_buffer, decrypt_buffer + out);
    return decrypted_data;
}

/*
Function that is called from Spicy. It's a wrapper around `process_data`;
it stores all the passed data in a global struct and then calls `process_data`,
which will eventually return the decrypted data and pass it back to Spicy.
*/
hilti::rt::Bytes decrypt_crypto_payload(
    const hilti::rt::Bytes &entire_packet,
    const hilti::rt::Bytes &connection_id,
    const hilti::rt::integer::safe<uint64_t> &encrypted_offset,
    const hilti::rt::integer::safe<uint64_t> &payload_offset,
    const hilti::rt::Bool &from_client)
{

    // Fill in the entire packet bytes
    std::vector<uint8_t> e_pkt;
    for (const auto &singlebyte : entire_packet)
    {
        e_pkt.push_back(singlebyte);
    }

    std::vector<uint8_t> cnnid;
    for (const auto &singlebyte : connection_id)
    {
        cnnid.push_back(singlebyte);
    }

    std::vector<uint8_t> initial_secret = hkdf_extract(cnnid);

    std::vector<uint8_t> server_client_secret;
    if (from_client)
    {
        server_client_secret = hkdf_expand(INITIAL_SECRET_LEN,
                                           initial_secret,
                                           CLIENT_INITIAL_INFO);
    }
    else
    {
        server_client_secret = hkdf_expand(INITIAL_SECRET_LEN,
                                           initial_secret,
                                           SERVER_INITIAL_INFO);
    }

    std::vector<uint8_t> key = hkdf_expand(AEAD_KEY_LEN,
                                           server_client_secret,
                                           KEY_INFO);
    std::vector<uint8_t> iv = hkdf_expand(AEAD_IV_LEN,
                                          server_client_secret,
                                          IV_INFO);
    std::vector<uint8_t> hp = hkdf_expand(AEAD_HP_LEN,
                                          server_client_secret,
                                          HP_INFO);

    DecryptionInformation decryptInfo = remove_header_protection(hp, (uint8_t)encrypted_offset, e_pkt);

    // Calculate the correct nonce for the decryption
    decryptInfo.nonce = calculate_nonce(iv, decryptInfo.packet_number);

    std::vector<uint8_t> decrypted_data = decrypt(key, e_pkt, payload_offset, decryptInfo);

    // Return it as hilti Bytes again
    hilti::rt::Bytes decr(decrypted_data.begin(), decrypted_data.end());
    return decr;
}
