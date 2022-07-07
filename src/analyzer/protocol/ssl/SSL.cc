#include "zeek/analyzer/protocol/ssl/SSL.h"

#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>

#include "zeek/Reporter.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/ssl/events.bif.h"
#include "zeek/analyzer/protocol/ssl/ssl_pac.h"
#include "zeek/analyzer/protocol/ssl/tls-handshake_pac.h"
#include "zeek/analyzer/protocol/tcp/TCP_Reassembler.h"
#include "zeek/util.h"

#ifdef OPENSSL_HAVE_KDF_H
#include <openssl/kdf.h>
#endif

#if defined(OPENSSL_VERSION_MAJOR) && (OPENSSL_VERSION_MAJOR >= 3)
#include <openssl/core_names.h>
#endif

namespace zeek::analyzer::ssl
	{

template <typename T> static inline T MSB(const T a)
	{
	return ((a >> 8) & 0xff);
	}

template <typename T> static inline T LSB(const T a)
	{
	return (a & 0xff);
	}

static std::basic_string<unsigned char> fmt_seq(uint32_t num)
	{
	std::basic_string<unsigned char> out(4, '\0');
	out.reserve(13);
	uint32_t netnum = htonl(num);
	out.append(reinterpret_cast<u_char*>(&netnum), 4);
	out.append(5, '\0');
	return out;
	}

SSL_Analyzer::SSL_Analyzer(Connection* c) : analyzer::tcp::TCP_ApplicationAnalyzer("SSL", c)
	{
	interp = new binpac::SSL::SSL_Conn(this);
	handshake_interp = new binpac::TLSHandshake::Handshake_Conn(this);
	had_gap = false;
	c_seq = 0;
	s_seq = 0;
	pia = nullptr;
	}

SSL_Analyzer::~SSL_Analyzer()
	{
	delete interp;
	delete handshake_interp;
	}

void SSL_Analyzer::Done()
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	handshake_interp->FlowEOF(true);
	handshake_interp->FlowEOF(false);
	}

void SSL_Analyzer::EndpointEOF(bool is_orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	handshake_interp->FlowEOF(is_orig);
	}

void SSL_Analyzer::StartEncryption()
	{
	interp->startEncryption(true);
	interp->startEncryption(false);
	interp->setEstablished();
	}

uint16_t SSL_Analyzer::GetNegotiatedVersion() const
	{
	return handshake_interp->chosen_version();
	}

void SSL_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	// We purposefully accept protocols other than TCP here. SSL/TLS are a bit special;
	// they are wrapped in a lot of other protocols. Some of them are UDP based - and provide
	// their own reassembly on top of UDP.
	if ( TCP() && TCP()->IsPartial() )
		return;

	if ( had_gap )
		// If only one side had a content gap, we could still try to
		// deliver data to the other side if the script layer can handle this.
		return;

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		AnalyzerViolation(util::fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void SSL_Analyzer::SendHandshake(uint16_t raw_tls_version, const u_char* begin, const u_char* end,
                                 bool orig)
	{
	handshake_interp->set_record_version(raw_tls_version);
	try
		{
		handshake_interp->NewData(orig, begin, end);
		}
	catch ( const binpac::Exception& e )
		{
		AnalyzerViolation(util::fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void SSL_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	had_gap = true;
	interp->NewGap(orig, len);
	}

void SSL_Analyzer::SetSecret(const zeek::StringVal& secret)
	{
	SetSecret(secret.Len(), secret.Bytes());
	}

void SSL_Analyzer::SetSecret(size_t len, const u_char* data)
	{
	secret.clear();
	secret.append((const char*)data, len);
	}

void SSL_Analyzer::SetKeys(const zeek::StringVal& nkeys)
	{
	keys.clear();
	keys.reserve(nkeys.Len());
	std::copy(nkeys.Bytes(), nkeys.Bytes() + nkeys.Len(), std::back_inserter(keys));
	}

void SSL_Analyzer::SetKeys(const std::vector<u_char> newkeys)
	{
	keys = std::move(newkeys);
	}

std::optional<std::vector<u_char>>
SSL_Analyzer::TLS12_PRF(const std::string& secret, const std::string& label,
                        const std::string& rnd1, const std::string& rnd2, size_t requested_len)
	{
#ifdef OPENSSL_HAVE_KDF_H
#if defined(OPENSSL_VERSION_MAJOR) && (OPENSSL_VERSION_MAJOR >= 3)
	// alloc context + params
	EVP_KDF* kdf = EVP_KDF_fetch(NULL, "TLS1-PRF", NULL);
	EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
	OSSL_PARAM params[4], *p = params;
	EVP_KDF_free(kdf);
#else /* OSSL 3 */
	// alloc buffers
	EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
#endif /* OSSL 3 */

	// prepare seed: seed = label + rnd1 + rnd2
	std::string seed{};
	seed.reserve(label.size() + rnd1.size() + rnd2.size());

	seed.append(label);
	seed.append(rnd1);
	seed.append(rnd2);

#if defined(OPENSSL_VERSION_MAJOR) && (OPENSSL_VERSION_MAJOR >= 3)
	// setup OSSL_PARAM array: digest, secret, seed
	// FIXME: sha384 should not be hardcoded
	// The const-cast is a bit ugly - but otherwise we have to copy the static string.
	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>(SN_sha384), 0);
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, (void*)secret.data(),
	                                         secret.size());
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, (void*)seed.data(), seed.size());
	*p = OSSL_PARAM_construct_end();

	auto keybuf = std::vector<u_char>(requested_len);

	// set OSSL params
	if ( EVP_KDF_CTX_set_params(kctx, params) <= 0 )
		goto abort;
	// derive key material
	if ( EVP_KDF_derive(kctx, keybuf.data(), requested_len, nullptr) <= 0 )
		goto abort;

	EVP_KDF_CTX_free(kctx);
	return keybuf;

abort:
	EVP_KDF_CTX_free(kctx);
	return {};
#else /* OSSL 3 */
	auto keybuf = std::vector<u_char>(requested_len);
	if ( EVP_PKEY_derive_init(pctx) <= 0 )
		goto abort; /* Error */
	// setup PKEY params: digest, secret, seed
	// FIXME: sha384 should not be hardcoded
	if ( EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_sha384()) <= 0 )
		goto abort; /* Error */
	if ( EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, secret.data(), secret.size()) <= 0 )
		goto abort; /* Error */
	if ( EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed.data(), seed.size()) <= 0 )
		goto abort; /* Error */
	if ( EVP_PKEY_derive(pctx, keybuf.data(), &requested_len) <= 0 )
		goto abort; /* Error */

	EVP_PKEY_CTX_free(pctx);
	return keybuf;

abort:
	EVP_PKEY_CTX_free(pctx);
#endif /* OSSL 3 */

#endif /* HAVE_KDF */
	return {};
	}

bool SSL_Analyzer::TryDecryptApplicationData(int len, const u_char* data, bool is_orig,
                                             uint8_t content_type, uint16_t raw_tls_version)
	{
	// Unsupported cipher suite. Currently supported:
	// - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 == 0xC030
	auto cipher = handshake_interp->chosen_cipher();
	if ( cipher != 0xC030 )
		{
		DBG_LOG(DBG_ANALYZER, "Unsupported cipher suite for decryption: %d\n", cipher);
		return false;
		}

	// Neither secret or key present: abort
	if ( secret.size() == 0 && keys.size() == 0 )
		{
		DBG_LOG(
			DBG_ANALYZER,
			"Could not decrypt packet due to missing keys/secret. Client_random: %s\n",
			util::fmt_bytes(reinterpret_cast<const char*>(handshake_interp->client_random().data()),
		                    handshake_interp->client_random().length()));
		// FIXME: change util function to return a printably std::string for DBG_LOG
		// print_hex("->client_random:", handshake_interp->client_random().data(),
		// handshake_interp->client_random().size());
		return false;
		}

	// Secret present, but no keys derived yet: derive keys
	if ( secret.size() != 0 && keys.size() == 0 )
		{
#ifdef OPENSSL_HAVE_KDF_H
		DBG_LOG(DBG_ANALYZER, "Deriving TLS keys for connection");
		uint32_t ts = htonl((uint32_t)handshake_interp->gmt_unix_time());

		auto c_rnd = handshake_interp->client_random();
		auto s_rnd = handshake_interp->server_random();

		std::string crand;
		crand.append(reinterpret_cast<char*>(&(ts)), 4);
		crand.append(reinterpret_cast<char*>(c_rnd.data()), c_rnd.length());
		std::string srand(reinterpret_cast<char*>(s_rnd.data()), s_rnd.length());

		// fixme - 72 should not be hardcoded
		auto res = TLS12_PRF(secret, "key expansion", srand, crand, 72);
		if ( ! res )
			{
			DBG_LOG(DBG_ANALYZER, "TLS PRF failed. Aborting.\n");
			return false;
			}

		// save derived keys
		SetKeys(res.value());
#else
		DBG_LOG(DBG_ANALYZER,
		        "Cannot derive TLS keys as Zeek was compiled without <openssl/kdf.h>");
		return false;
#endif
		}

	// Keys present: decrypt TLS application data
	if ( keys.size() == 72 )
		{
		// FIXME: could also print keys or conn id here
		DBG_LOG(DBG_ANALYZER, "Decrypting application data");

		// NOTE: you must not call functions that invalidate keys.data() on keys during the
		// remainder of this function. (Given that we do not manipulate the key material in this
		// function that should not be hard)

		// client write_key
		const u_char* c_wk = keys.data();
		// server write_key
		const u_char* s_wk = keys.data() + 32;
		// client IV
		const u_char* c_iv = keys.data() + 64;
		// server IV
		const u_char* s_iv = keys.data() + 68;

		// FIXME: should we change types here?
		u_char* encrypted = (u_char*)data;
		size_t encrypted_len = len;

		if ( is_orig )
			c_seq++;
		else
			s_seq++;

		// AEAD nonce, length 12
		std::basic_string<unsigned char> s_aead_nonce;
		if ( is_orig )
			s_aead_nonce.assign(c_iv, 4);
		else
			s_aead_nonce.assign(s_iv, 4);

		// this should be the explicit counter
		s_aead_nonce.append(encrypted, 8);
		assert(s_aead_nonce.size() == 12);

		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		EVP_CIPHER_CTX_init(ctx);
		EVP_CipherInit(ctx, EVP_aes_256_gcm(), NULL, NULL, 0);

		encrypted += 8;
		// FIXME: is this because of nonce and aead tag?
		if ( encrypted_len <= (16 + 8) )
			{
			DBG_LOG(DBG_ANALYZER, "Invalid encrypted length encountered during TLS decryption");
			EVP_CIPHER_CTX_free(ctx);
			return false;
			}
		encrypted_len -= 8;
		encrypted_len -= 16;

		// FIXME: aes_256_gcm should not be hardcoded here ;)
		if ( is_orig )
			EVP_DecryptInit(ctx, EVP_aes_256_gcm(), c_wk, s_aead_nonce.data());
		else
			EVP_DecryptInit(ctx, EVP_aes_256_gcm(), s_wk, s_aead_nonce.data());

		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, encrypted + encrypted_len);

		// AEAD tag
		std::basic_string<unsigned char> s_aead_tag;
		if ( is_orig )
			s_aead_tag = fmt_seq(c_seq);
		else
			s_aead_tag = fmt_seq(s_seq);

		s_aead_tag[8] = content_type;
		s_aead_tag[9] = MSB(raw_tls_version);
		s_aead_tag[10] = LSB(raw_tls_version);
		s_aead_tag[11] = MSB(encrypted_len);
		s_aead_tag[12] = LSB(encrypted_len);
		assert(s_aead_tag.size() == 13);

		auto decrypted = std::vector<u_char>(
			encrypted_len +
			16); // see OpenSSL manpage - 16 is the block size for the supported cipher
		int decrypted_len = 0;

		EVP_DecryptUpdate(ctx, NULL, &decrypted_len, s_aead_tag.data(), s_aead_tag.size());
		EVP_DecryptUpdate(ctx, decrypted.data(), &decrypted_len, (const u_char*)encrypted,
		                  encrypted_len);
		assert(static_cast<decltype(decrypted.size())>(decrypted_len) <= decrypted.size());
		decrypted.resize(decrypted_len);

		int res = 0;
		if ( ! (res = EVP_DecryptFinal(ctx, NULL, &res)) )
			{
			DBG_LOG(DBG_ANALYZER, "Decryption failed with return code: %d. Invalid key?\n", res);
			EVP_CIPHER_CTX_free(ctx);
			return false;
			}

		DBG_LOG(DBG_ANALYZER, "Successfully decrypted %d bytes.", decrypted_len);
		EVP_CIPHER_CTX_free(ctx);
		ForwardDecryptedData(decrypted, is_orig);

		return true;
		}

	// This is only reached if key derivation fails or is unsupported
	return false;
	}

void SSL_Analyzer::ForwardDecryptedData(const std::vector<u_char>& data, bool is_orig)
	{
	if ( ! pia )
		{
		pia = new analyzer::pia::PIA_TCP(Conn());
		if ( AddChildAnalyzer(pia) )
			{
			pia->FirstPacket(true, nullptr);
			pia->FirstPacket(false, nullptr);
			}
		else
			reporter->Error("Could not initialize PIA");
		}

	ForwardStream(data.size(), data.data(), is_orig);
	}

bool SSL_Analyzer::GetFlipped()
	{
	return handshake_interp->flipped();
	}

	} // namespace zeek::analyzer::ssl
