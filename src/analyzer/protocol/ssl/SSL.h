#pragma once

#include "zeek/analyzer/protocol/pia/PIA.h"
#include "zeek/analyzer/protocol/ssl/events.bif.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace binpac
	{
namespace SSL
	{
class SSL_Conn;
	}
	}

namespace binpac
	{
namespace TLSHandshake
	{
class Handshake_Conn;
	}
	}

namespace zeek::analyzer::ssl
	{

class SSL_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer
	{
	// let binpac forward encrypted TLS application data to us.
	friend class binpac::SSL::SSL_Conn;

public:
	explicit SSL_Analyzer(Connection* conn);
	~SSL_Analyzer() override;

	// Overridden from Analyzer.
	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;

	void SendHandshake(uint16_t raw_tls_version, const u_char* begin, const u_char* end, bool orig);

	// Tell the analyzer that encryption has started.
	void StartEncryption();
	// Get the TLS version that the server chose. 0 if not yet known.
	uint16_t GetNegotiatedVersion() const;

	// Overridden from analyzer::tcp::TCP_ApplicationAnalyzer.
	void EndpointEOF(bool is_orig) override;

	static analyzer::Analyzer* Instantiate(Connection* conn) { return new SSL_Analyzer(conn); }

	/**
	 * Set the secret that should be used to derive keys for the
	 * connection. (For TLS 1.2 this is the pre-master secret)
	 *
	 * Please note that these functions currently are hardcoded to only work with a single TLS 1.2
	 * ciphersuite (TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384).
	 *
	 * @param secret The secret to set
	 */
	void SetSecret(const StringVal& secret);

	/**
	 * Set the secret that should be used to derive keys for the
	 * connection. (For TLS 1.2 this is the pre-master secret)
	 *
	 * Please note that these functions currently are hardcoded to only work with a single TLS 1.2
	 * ciphersuite (TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384).
	 *
	 * @param len Length of the secret bytes
	 *
	 * @param data Pointer to the secret bytes
	 */
	void SetSecret(size_t len, const u_char* data);

	/**
	 * Set the decryption keys that should be used to decrypt
	 * TLS application data in the connection.
	 *
	 * Please note that these functions currently are hardcoded to only work with a single TLS 1.2
	 * ciphersuite (TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384).
	 *
	 * @param keys The key buffer as derived via TLS PRF (for
	 * AES_GCM this should be 72 bytes in length)
	 */
	void SetKeys(const StringVal& keys);

	/**
	 * Set the decryption keys that should be used to decrypt
	 * TLS application data in the connection.
	 *
	 * Please note that these functions currently are hardcoded to only work with a single TLS 1.2
	 * ciphersuite (TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384).
	 *
	 * @param keys The key buffer as derived via TLS PRF (for
	 * AES_GCM this should be 72 bytes in length)
	 */
	void SetKeys(const std::vector<u_char> newkeys);

	/**
	 * Check if the connection is flipped--meaning that the TLS client is the responder of the
	 * connection.
	 *
	 * @return True if connection is flipped.
	 */
	bool GetFlipped();

protected:
	/**
	 * Try to decrypt TLS application data from a packet. Requires secret or keys to be set prior.
	 *
	 * Please note that these functions currently are hardcoded to only work with a single TLS 1.2
	 * ciphersuite (TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384).
	 *
	 * @param len Length of the encrypted bytes to decrypt
	 *
	 * @param data Pointer to the encrypted bytes to decrypt
	 *
	 * @param is_orig Direction of the connection
	 *
	 * @param content_type Content type as given in the TLS packet
	 *
	 * @param raw_tls_version Raw TLS version as given in the TLS packets
	 *
	 * @return True if decryption succeeded and data was forwarded.
	 */
	bool TryDecryptApplicationData(int len, const u_char* data, bool is_orig, uint8_t content_type,
	                               uint16_t raw_tls_version);

	/**
	 * TLS 1.2 pseudo random function (PRF) used to expand the pre-master secret and derive keys.
	 * The seed is obtained by concatenating rnd1 and rnd2.
	 *
	 * Please note that these functions currently are hardcoded to only work with a single TLS 1.2
	 * ciphersuite (TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384).
	 *
	 * @param secret Secret as defined in the TLS RFC
	 *
	 * @param label Label as defined in the TLS RFC
	 *
	 * @param First part of the seed
	 *
	 * @param rnd2 Second part of the seed
	 *
	 * @param rnd2_len Length of the second part of the seed
	 *
	 * @param requested_len Length indicating how many bytes should be derived
	 *
	 * @return The derived bytes, if the operation succeeds.
	 */
	std::optional<std::vector<u_char>> TLS12_PRF(const std::string& secret,
	                                             const std::string& label, const std::string& rnd1,
	                                             const std::string& rnd2, size_t requested_len);

	/**
	 * Forward decrypted TLS application data to child analyzers.
	 *
	 * @param data Data to forward
	 *
	 * @param is_orig Direction of the connection
	 */
	void ForwardDecryptedData(const std::vector<u_char>& data, bool is_orig);

	binpac::SSL::SSL_Conn* interp;
	binpac::TLSHandshake::Handshake_Conn* handshake_interp;
	bool had_gap;

	// client and server sequence number, used for TLS 1.2 decryption
	int c_seq;
	int s_seq;
	// secret, for decyption
	std::string secret;
	// derived keys, for decryption
	std::vector<u_char> keys;
	// PIA, for decrypted data
	zeek::analyzer::pia::PIA_TCP* pia;
	};

	} // namespace zeek::analyzer::ssl
