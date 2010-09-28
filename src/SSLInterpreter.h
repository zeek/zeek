// $Id: SSLInterpreter.h 5988 2008-07-19 07:02:12Z vern $

#ifndef sslinterpreter_h
#define sslinterpreter_h

#include "util.h"
#include "SSLProxy.h"

// --- forward declarations ----------------------------------------------------

class SSLProxy_Analyzer;
class Contents_SSL;
class SSL_InterpreterEndpoint;
class SSL_DataBlock;

// --- SSL_Interpreter --------------------------------------------------------

/*!
 * \brief This class is the abstract base-class for the different ssl
 *        interpreters used for the different ssl versions.
 *
 * Since there is currently no support in Bro for a change of the connection
 * type (IMAP -> TLS, for example), we decided not to inherit from the class
 * Connection. This way, we can easily switch to SSLv3x after we've seen (and
 * analyzed) a SSLv2 client hello record with a version number > SSLv2.
 *
 * There currently two (non-abstract) interpreters: SSLv2_Interpreter and
 * SSLv3_Interpreter. The first one supports SSL 2.0, the second one supports
 * both SSL 3.0 and SSL 3.1/TLS 1.0.
 *
 * See SSLProxy_Analyzer for additional information.
 */
class SSL_Interpreter {
public:
	SSL_Interpreter(SSLProxy_Analyzer* proxy);
	virtual ~SSL_Interpreter();

	static uint32 analyzedCertificates; ///< how often analyzeCertificate() has been called
	static uint32 verifiedCertificates; ///< how many certificates have actually been verified
	static uint32 failedCertificates;   ///< how many certificates have failed verification
	static uint32 certificateChains;    ///< counter for certificate chains

	// In order to initialize the correct SSL_InterpreterEndpoints,
	// override it in the corresponding subclass.
	virtual void BuildInterpreterEndpoints() = 0;
	virtual void Init();

	SSL_InterpreterEndpoint* Orig() const;
	SSL_InterpreterEndpoint* Resp() const;
	SSLProxy_Analyzer* Proxy() const;
	int Is_Orig(SSL_InterpreterEndpoint* p) const;

	virtual void analyzeCertificate(SSL_InterpreterEndpoint* s,
					 const u_char* data, int length,
					 uint8 type, bool isChain);

	void Weird(const char* name) const;

	static void printStats();

	void fire_ssl_conn_attempt(uint16 sslVersion,
					TableVal* currentCipherSuites);
	void fire_ssl_conn_server_reply(uint16 sslVersion,
					TableVal* currentCipherSuites);
	void fire_ssl_conn_established(uint16 sslVersion, uint32 cipherSuite);
	void fire_ssl_conn_reused(const SSL_DataBlock* pData);
	void fire_ssl_conn_alert(uint16 sslVersion, uint16 level,
					uint16 description);

protected:
	TableVal* MakeSessionID(const u_char* data, int len);

	SSLProxy_Analyzer* proxy;
	SSL_InterpreterEndpoint* orig;
	SSL_InterpreterEndpoint* resp;
};

// --- SSL_InterpreterEndpoint ------------------------------------------------

/*!
 * \brief This abstract class represents the SSL_InterpreterEndpoints for the
 *        SSL_Interpreter.
 *
 * The key-method is Deliver() which receives the ssl records
 * from the SSLProxy_Analyzer. So overwrite the Deliver()-method and do
 * whatever analysis on the record content (and/or pass it to the corresponding
 * SSL_Interpreter).
 */
class SSL_InterpreterEndpoint {
public:
	SSL_InterpreterEndpoint(SSL_Interpreter* interpreter, bool is_orig);
	virtual ~SSL_InterpreterEndpoint();

	/**This method is called by corresponding SSLProxy_Analyzer and
	 * delivers the data.
	 * @param t time, when the segment was received by bro (?)
	 * @param len length of TCP-Segment
	 * @param data content of TCP-Segment
	 */
	virtual void Deliver(int len, const u_char* data) = 0;
	bool isDataPending();
	void SetPeer(SSL_InterpreterEndpoint* p);
	int IsOrig() const;
	SSL_InterpreterEndpoint* Peer() const;
	SSL_Interpreter* Interpreter() const;

	Contents_SSL* GetProxyEndpoint()	{ return proxyEndpoint; }

	void SetProxyEndpoint(Contents_SSL* proxyEndpoint);

protected:
	SSL_Interpreter* interpreter;  ///< Pointer to the SSL_Interpreter to which this endpoint belongs to
	SSL_InterpreterEndpoint* peer; ///< Pointer to the peer of this endpoint
	Contents_SSL* proxyEndpoint; ///< Pointer to the corresponding Contents_SSL
	bool ourProxyEndpoint;	// true if we need to delete the proxyEndpoint
	int is_orig;                   ///< true if this endpoint is the originator of the connection, false otherwise
};

// --- class CertStore --------------------------------------------------------
/*!
 * \brief This class is used to store some information about a X509 certificate.
 *
 * To save memory, we only store some characteristic criterias about a
 * certificate, that's currently it's size and a hashsum.
 *
 * \note This class is currently <b>experimental</b>.
 */
class CertStore {
public:
	uint32 ip_addr; ///< ip address where this certificate is from
	uint32 port;    ///< port number where this certificate is from

	int certSize;    ///< size of the certificate in bytes
	hash_t certHash; ///< hashsum obver the entire certificate
	int isValid;     ///< boolean value indicating if the certificate is valid
	int changes;     ///< counter for how often this certificate has changed for the above ip + port number

	CertStore(uint32 ip, uint32 port, hash_t hash, int size);
	bool isSameCert(hash_t hash, int length);
};

#endif
