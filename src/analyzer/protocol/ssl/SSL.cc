#include "zeek/analyzer/protocol/ssl/SSL.h"

#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/tcp/TCP_Reassembler.h"
#include "zeek/Reporter.h"
#include "zeek/util.h"

#include "zeek/analyzer/protocol/ssl/events.bif.h"
#include "zeek/analyzer/protocol/ssl/ssl_pac.h"
#include "zeek/analyzer/protocol/ssl/tls-handshake_pac.h"

#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

static void print_hex(std::string name, u_char* data, int len)
	{
	int i = 0;
	printf("%s (%d): ", name.c_str(), len);
	if (len > 0)
		printf("0x%02x", data[0]);

	for (i = 1; i < len; i++)
		{
		printf(" 0x%02x", data[i]);
		}
	printf("\n");
	}

static bool tls1_prf(const u_char *secret, int secret_len, const char* label,
		const u_char* rnd1, int rnd1_len, const u_char* rnd2, int rnd2_len, u_char* out, size_t out_len)
	{
	// alloc buffers
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
	size_t seed_len = strlen(label) + rnd1_len + rnd2_len;
	u_char *seed = (u_char*) malloc(seed_len);
	u_char *ptr = seed;

	// seed = label + rnd1 + rnd2
	memcpy(ptr, label, strlen(label));
	ptr += strlen(label);
	memcpy(ptr, rnd1, rnd1_len);
	ptr += rnd1_len;
	memcpy(ptr, rnd2, rnd2_len);
	ptr += rnd2_len;

	if (EVP_PKEY_derive_init(pctx) <= 0)
		goto abort; /* Error */
	// FIXME: sha384 should not be hardcoded
	if (EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_sha384()) <= 0)
		goto abort; /* Error */
	if (EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, secret, secret_len) <= 0)
		goto abort; /* Error */
	if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed, seed_len) <= 0)
		goto abort; /* Error */
	if (EVP_PKEY_derive(pctx, out, &out_len) <= 0)
		goto abort; /* Error */

	EVP_PKEY_CTX_free(pctx);
	free(seed);
	return true;

abort:
	EVP_PKEY_CTX_free(pctx);
	free(seed);
	return false;
	}

namespace zeek::analyzer::ssl {

#define MSB(a) ((a>>8)&0xff)
#define LSB(a) (a&0xff)

static void fmt_seq(uint32_t num, u_char* buf)
	{
	memset(buf, 0, 8);
	uint32_t netnum = htonl(num);
	memcpy(buf+4, &netnum, 4);
	}

SSL_Analyzer::SSL_Analyzer(Connection* c)
: analyzer::tcp::TCP_ApplicationAnalyzer("SSL", c)
	{
	interp = new binpac::SSL::SSL_Conn(this);
	handshake_interp = new binpac::TLSHandshake::Handshake_Conn(this);
	had_gap = false;
	c_seq = 0;
	s_seq = 0;
	// FIXME: should this be initialized to nullptr?
	secret = new zeek::StringVal(0, "");
	keys = new zeek::StringVal(0, "");
	pia = nullptr;
	}

SSL_Analyzer::~SSL_Analyzer()
	{
	delete interp;
	delete handshake_interp;
	delete secret;
	delete keys;
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
		ProtocolViolation(util::fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void SSL_Analyzer::SendHandshake(uint16_t raw_tls_version, const u_char* begin, const u_char* end, bool orig)
	{
	handshake_interp->set_record_version(raw_tls_version);
	try
		{
		handshake_interp->NewData(orig, begin, end);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(util::fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void SSL_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	had_gap = true;
	interp->NewGap(orig, len);
	}

void SSL_Analyzer::SetSecret(const u_char* data, int len)
	{
	// FIXME: Is this the proper way to initialize a zeek::StringVal?
	//        the alternative requires a cast: new zeek::StringVal(len, data)
	secret = new zeek::StringVal(new zeek::String(data, len, true));
	}

void SSL_Analyzer::SetKeys(const u_char* data, int len)
	{
	keys = new zeek::StringVal(new zeek::String(data, len, true));
	}

bool SSL_Analyzer::TryDecryptApplicationData(int len, const u_char* data, bool is_orig, uint8_t content_type, uint16_t raw_tls_version)
	{
	// Unsupported cipher suite. Currently supported:
	// - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 == 0xC030
	auto cipher = handshake_interp->chosen_cipher();
	if ( cipher != 0xC030 )
		{
		DBG_LOG(DBG_ANALYZER, "Unsupported cipher suite: %d\n", cipher);
		return false;
		}

	// Neither secret or key present: abort
	if ( secret->Len() == 0 && keys->Len() == 0 )
		{
		DBG_LOG(DBG_ANALYZER, "Could not decrypt packet due to missing key\n");
		print_hex("->client_random:", handshake_interp->client_random().data(), handshake_interp->client_random().length());
		return false;
		}

	// Secret present, but no keys derived yet: derive keys
	if ( secret->Len() != 0 && keys->Len() == 0 )
		{
		uint32_t ts = htonl((uint32_t) handshake_interp->gmt_unix_time());

		u_char crand[32] = {0x00};
		u_char keybuf[72];

		auto c_rnd = handshake_interp->client_random();
		auto s_rnd = handshake_interp->server_random();
		memcpy(crand, &(ts), 4);
		memcpy(crand + 4, c_rnd.data(), c_rnd.length());

		tls1_prf(secret->Bytes(), secret->Len(), "key expansion", s_rnd.data(), s_rnd.length(),
				crand, sizeof(crand), keybuf, sizeof(keybuf));

		// save derived keys
		SetKeys(keybuf, sizeof(keybuf));
	}

	// Keys present: decrypt TLS application data
	if ( keys->Len() != 0 )
		{
		// session keys & AEAD data
		u_char c_wk[32];
		u_char s_wk[32];
		u_char c_iv[4];
		u_char s_iv[4];
		u_char s_aead_nonce[12];
		u_char s_aead_tag[13];

		memcpy(c_wk, keys->Bytes(), 32);
		memcpy(s_wk, &(keys->Bytes()[32]), 32);
		memcpy(c_iv, &(keys->Bytes()[64]), 4);
		memcpy(s_iv, &(keys->Bytes()[68]), 4);

		// FIXME: should we change types here?
		u_char* encrypted = (u_char*)data;
		size_t encrypted_len = len;

		// FIXME: should this be moved to SSL_Conn?
		if ( is_orig )
			c_seq++;
		else
			s_seq++;

		if ( is_orig )
			memcpy(s_aead_nonce, c_iv, 4);
		else
			memcpy(s_aead_nonce, s_iv, 4);
		memcpy(&(s_aead_nonce[4]), encrypted, 8);

		EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
		EVP_CIPHER_CTX_init(ctx);
		EVP_CipherInit(ctx, EVP_aes_256_gcm(), NULL, NULL, 0);

		encrypted += 8;
		// FIXME: is this because of nonce and aead tag?
		encrypted_len -= 8;
		encrypted_len -= 16;

		if (is_orig)
			EVP_DecryptInit(ctx, EVP_aes_256_gcm(), c_wk, s_aead_nonce);
		else
			EVP_DecryptInit(ctx, EVP_aes_256_gcm(), s_wk, s_aead_nonce);
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, encrypted + encrypted_len);

		if (is_orig)
			fmt_seq(c_seq, s_aead_tag);
		else
			fmt_seq(s_seq, s_aead_tag);

		s_aead_tag[8] = content_type;
		s_aead_tag[9] = MSB(raw_tls_version);
		s_aead_tag[10] = LSB(raw_tls_version);
		s_aead_tag[11] = MSB(encrypted_len);
		s_aead_tag[12] = LSB(encrypted_len);

		u_char *decrypted = (u_char*)malloc(encrypted_len);
		int decrypted_len = 0;

		EVP_DecryptUpdate(ctx, NULL, &decrypted_len, s_aead_tag, 13);
		EVP_DecryptUpdate(ctx, decrypted, &decrypted_len, (const u_char*) encrypted, encrypted_len);

		int res = 0;
		if ( ! (res = EVP_DecryptFinal(ctx, NULL, &res)) )
			{
			DBG_LOG(DBG_ANALYZER, "Decryption failed with return code: %d. Invalid key?\n", res);
			EVP_CIPHER_CTX_free(ctx);
			free(decrypted);
			return false;
			}

		EVP_CIPHER_CTX_free(ctx);
		ForwardDecryptedData(decrypted_len, reinterpret_cast<const u_char*>(decrypted), is_orig);

		free(decrypted);
		return true;
	}

	// This is only reached if key derivation somehow failed
	return false;
	}

void SSL_Analyzer::ForwardDecryptedData(int len, const u_char* data, bool is_orig)
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
			reporter->FatalError("Could not initialize PIA");

		// FIXME: Also statically add HTTP/H2 at the moment.
		//        We should move this bit to scriptland
		auto http = analyzer_mgr->InstantiateAnalyzer("HTTP", Conn());
		if ( http )
			AddChildAnalyzer(http);
		auto http2 = analyzer_mgr->InstantiateAnalyzer("HTTP2", Conn());
		if ( http2 )
			AddChildAnalyzer(http2);
		}

	ForwardStream(len, data, is_orig);
	}

} // namespace zeek::analyzer::ssl
