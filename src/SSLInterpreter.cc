// $Id: SSLInterpreter.cc 5988 2008-07-19 07:02:12Z vern $

#include "SSLInterpreter.h"
#include "SSLv2.h"

#ifdef USE_OPENSSL
#include "X509.h"
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

declare(PDict, CertStore);
PDict(CertStore) cert_states;

// --- Initalization of static variables --------------------------------------

uint32 SSL_Interpreter::analyzedCertificates = 0;
uint32 SSL_Interpreter::verifiedCertificates = 0;
uint32 SSL_Interpreter::failedCertificates = 0;
uint32 SSL_Interpreter::certificateChains = 0;

// --- SSL_Interpreter --------------------------------------------------------

/*!
 * The constructor.
 *
 * \param proxy Pointer to the SSLProxy_Analyzer which created this instance.
 */
SSL_Interpreter::SSL_Interpreter(SSLProxy_Analyzer* proxy)
	{
	this->proxy = proxy;
	}

/*!
 * The destructor.
 */
SSL_Interpreter::~SSL_Interpreter()
	{
	delete orig;
	delete resp;
	}

/*!
 * Analogous to TCP_Connection::Init(), this method calls
 * BuildInterpreterEndpoints() to create the corresponding endpoints.
 */
void SSL_Interpreter::Init()
	{
	BuildInterpreterEndpoints();
	orig->SetPeer(resp);
	resp->SetPeer(orig);
	}

/*!
 * This method analyzes a given certificate (chain), using the OpenSSL library.
 *
 * \param s Pointer to the SSL_InterpreterEndpoint which received the
 *          cerificate (chain).
 * \param data Pointer to the data block which contains the certificate (chain).
 * \param length Size of the data block.
 * \param type the certificate type
 * \param isChain false if data is pointing to a single certificate,
 *                true if data is pointing to a certificate chain
 * mod by scott in:
 *       uint32 ip_address = *(s->proxyEndpoint->Endpoint()->dst_addr);
 *       uint16 port = (uint16) s->proxyEndpoint->Endpoint()->conn->RespPort();
 * inserting endpoint
 */
void SSL_Interpreter::analyzeCertificate(SSL_InterpreterEndpoint* s,
			const u_char* data, int length, uint8 type, bool isChain)
	{
	// See if we should continue with this certificate.
	if ( ssl_certificate_seen )
		{
		val_list* vl = new val_list;
		vl->append(proxy->BuildConnVal());
		vl->append(new Val(! s->IsOrig(), TYPE_BOOL));
		proxy->ConnectionEvent(ssl_certificate_seen, vl);
		}

	++analyzedCertificates;

	const u_char* pCert = data;
	uint32 certLength = length;
	uint certCount = 0;

	if ( isChain )
		{
		++certificateChains;

		// Sum of all cert sizes has to match certListLength.
		int tempLength = 0;
		while ( tempLength < length )
			{
			++certCount;
			uint32 certLength =
				uint32((data[tempLength + 0] << 16) |
					data[tempLength + 1] << 8) |
				data[tempLength + 2];

			tempLength += certLength + 3;
			}

		if ( tempLength > length )
			{
			Weird( "SSLv3x: sum of size of certificates doesn't match size of certificate chain" );
			return;
			}

		// Get the first certificate.
		pCert = data + 3;
		certLength = uint32((data[0] << 16) | data[1] << 8) | data[2];
		}

	// Create a hashsum of the current certificate.
	hash_t hashsum = HashKey::HashBytes(pCert, certLength);

	if ( ! proxy->TCP() )
		return;

	TCP_Endpoint* endp = s->IsOrig() ? proxy->TCP()->Orig() : proxy->TCP()->Resp();

	// Check if we've seen a certificate from this addr/port before.
	uint8 key[6];
	// ### Won't work for IPv6.
	uint32 ip_address = *(endp->dst_addr);
	uint16 port = uint16(proxy->Conn()->RespPort());
	memcpy(key, &ip_address, 4);
	memcpy(&key[4], &port, 2);

	HashKey h(key, sizeof(key));
	CertStore* pCertState = 0;
	pCertState = (CertStore*) cert_states.Lookup(&h);
	if ( ! pCertState )
		{ // new address
		pCertState = new CertStore(ip_address, port, hashsum, certLength);
		cert_states.Insert(&h, pCertState);
		}
	else
		{
		// We've seen this address/certificate before.  Check if
		// certificate changed.
		if ( ! pCertState->isSameCert(hashsum, certLength) )
			{
			// This shouldn't happen; ### make a stronger error.
			Weird("SSL: Certificate changed for this ip+port !!!");

			// Update status.
			++pCertState->changes;
			pCertState->certHash = hashsum;
			pCertState->certSize = certLength;
			pCertState->isValid = -1;
			}
		else
			{ // cert didn't change
			if ( pCertState->isValid == 0 )
				{
				// This is an invalid cert, but we
				// warned before.
				}

			// Save time - don't analyze it any further.
			return;
			}
		}

	// Certificate verification.
	if ( ssl_verify_certificates != 0 )
		{
		++verifiedCertificates;
		int invalid = 0;
		switch ( type ) {
		case SSLv2_CT_X509_CERTIFICATE:
#ifdef USE_OPENSSL
			if ( ! isChain )
				invalid = X509_Cert::verify(s->GetProxyEndpoint(),
							pCert, certLength);
			else
				invalid = X509_Cert::verifyChain(s->GetProxyEndpoint(),
							data, length);
#else
			proxy->Weak("SSL: Could not verify certificate (missing OpenSSL support)!");
			invalid = 0;
#endif
			break;

		default:
			Weird("SSL: Unknown CERTIFICATE-TYPE!");
			invalid = 1; // quick 'n dirty :)
			break;
		}

		if ( invalid )
			{
			proxy->Weak("SSL: Certificate check FAILED!");
			pCertState->isValid = 0;
			++failedCertificates;
			}
		else
			pCertState->isValid = 1;
		}

	// Store the certificate.
	if ( ssl_store_certificates != 0 )
		{
		// Let's hope the address is currently in network byte order!
		in_addr addr;
		addr.s_addr = ip_address;
		char* pDummy = inet_ntoa(addr);
		char sFileName[PATH_MAX];

		if ( ssl_store_cert_path && 
		     ssl_store_cert_path->AsString()->Len() > 0 )
			{
			const BroString* pString = ssl_store_cert_path->AsString();
			safe_snprintf(sFileName, PATH_MAX, "%s/cert.%s-server-c%i.der",
				      pString->Bytes(), pDummy, pCertState->changes);
			}
		else
			safe_snprintf(sFileName, PATH_MAX, "cert.%s-server-c%i.der",
				      pDummy, pCertState->changes);

		FILE* certFile = fopen(sFileName, "wb");
		if ( ! certFile )
			{
			Weird(fmt("SSL_Interpreter::analyzeCertificate(): Error opening '%s'!\n", sFileName));
			return;
			}

		fwrite(pCert, 1, certLength, certFile);
		fclose(certFile);
		}

	// TODO: test if cert is valid for the address we got it from.
	}


/*!
 * \return the originating SSL_InterpreterEndpoint
 */
SSL_InterpreterEndpoint* SSL_Interpreter::Orig() const
	{
	return orig;
	}

/*!
 * \return the responding SSL_InterpreterEndpoint
 */
SSL_InterpreterEndpoint* SSL_Interpreter::Resp() const
	{
	return resp;
	}

/*!
 * \param p Pointer to an SSL_InterpreterEndpoint to test
 *
 * \return true if p is the originating SSL_InterpreterEndpoint,
 *         false otherwise
 */
int SSL_Interpreter::Is_Orig(SSL_InterpreterEndpoint* p) const
	{
	return p == orig;
	}

/*!
 * \return the responding SSL_InterpreterEndpoint
 */
SSLProxy_Analyzer* SSL_Interpreter::Proxy() const
	{
	return proxy;
	}

/*!
 * This methods prints a string into the "weird" log file.
 *
 * \param name String to log into the "weird" file.
 */
void SSL_Interpreter::Weird(const char* name) const
	{
	proxy->Weird(name);
	}

/*!
 * Prints some counters.
 */
void SSL_Interpreter::printStats()
	{
	printf("SSL_Interpreter:\n");
	printf("analyzedCertificates = %u\n", analyzedCertificates);
	printf("verifiedCertificates = %u\n", verifiedCertificates);
	printf("failedCertificates = %u\n", failedCertificates);
	printf("certificateChains = %u\n", certificateChains);
	}

/*!
 * Wrapper function for the event ssl_conn_attempt.
 *
 * \param sslVersion the SSL version for which the event occured
 *
 * \see SSLProxy_Analyzer::SSL_Versions
 */
void SSL_Interpreter::fire_ssl_conn_attempt(uint16 sslVersion,
						TableVal* currentCipherSuites)
	{
	EventHandlerPtr event = ssl_conn_attempt;
	if ( event )
		{
		val_list* vl = new val_list;
		vl->append(proxy->BuildConnVal());
		vl->append(new Val(sslVersion, TYPE_INT));
		vl->append(currentCipherSuites);

		proxy->ConnectionEvent(event, vl);
		}
	}

/*!
 * Wrapper function for the event ssl_conn_server_reply.
 *
 * \param sslVersion the SSL version for which the event occured
 *
 * \see SSLProxy_Analyzer::SSL_Versions
 */
void SSL_Interpreter::fire_ssl_conn_server_reply(uint16 sslVersion,
						TableVal* currentCipherSuites)
	{
	EventHandlerPtr event = ssl_conn_server_reply;
	if ( event )
		{
		val_list* vl = new val_list;
		vl->append(proxy->BuildConnVal());
		vl->append(new Val(sslVersion, TYPE_INT));
		vl->append(currentCipherSuites);

		proxy->ConnectionEvent(event, vl);
		}
	}

/*!
 * Wrapper function for the event ssl_conn_established.
 *
 * \param sslVersion the SSL version for which the event occured
 * \param cipherSuite constant indicating the used SSL cipher suite
 *
 * \see SSLProxy_Analyzer::SSL_Versions, SSLv2_CipherSpecs and SSL3_1_CipherSpec.
 */
void SSL_Interpreter::fire_ssl_conn_established(uint16 sslVersion,
						uint32 cipherSuite)
	{
	EventHandlerPtr event = ssl_conn_established;
	if ( event )
		{
		val_list* vl = new val_list;
		vl->append(proxy->BuildConnVal());
		vl->append(new Val(sslVersion, TYPE_INT));
		vl->append(new Val(cipherSuite, TYPE_COUNT));

		proxy->ConnectionEvent(event, vl);
		}

	}

/*!
 * Wrapper function for the event ssl_conn_reused
 *
 * \param pData Pointer to a SSL_DataBlock which contains the SSL session ID
 *        of the originating ssl session.
 */
void SSL_Interpreter::fire_ssl_conn_reused(const SSL_DataBlock* pData)
	{
	EventHandlerPtr event = ssl_conn_reused;
	if ( event )
		{
		val_list* vl = new val_list;
		vl->append(proxy->BuildConnVal());
		vl->append(MakeSessionID(pData->data, pData->len));
		proxy->ConnectionEvent(event, vl);
		}
	}

/*!
 * Wrapper function for the event ssl_conn_alert
 *
 * \param sslVersion the SSL version for which the event occured
 * \param level constant indicating the level of severity
 * \param description constant indicating the type of alert/error
 *
 * \see SSLProxy_Analyzer::SSL_Versions, SSL3x_AlertLevel, SSL3_1_AlertDescription
 *      and SSLv2_ErrorCodes.
 */
void SSL_Interpreter::fire_ssl_conn_alert(uint16 sslVersion, uint16 level,
						uint16 description)
	{
	if ( ssl_conn_alert )
		{
		EventHandlerPtr event = ssl_conn_alert;
		if ( event )
			{
			val_list* vl = new val_list;
			vl->append(proxy->BuildConnVal());
			vl->append(new Val(sslVersion, TYPE_INT));
			vl->append(new Val(level, TYPE_COUNT));
			vl->append(new Val(description, TYPE_COUNT));

			proxy->ConnectionEvent(event, vl);
			}
		}
	}

// Generate a session ID table.  Returns an empty table
// if len is zero.
TableVal* SSL_Interpreter::MakeSessionID(const u_char* data, int len)
	{
	TableVal* sessionIDTable = new TableVal(SSL_sessionID);

	if ( ! len )
		return sessionIDTable;

	for ( int i = 0; i < len; i += 4 )
		{
		uint32 temp = (data[i] << 24) | (data[i + 1] << 16) |
			      (data[i + 2] << 8) | data[i + 3];

		Val* index = new Val(i / 4, TYPE_COUNT);

		sessionIDTable->Assign(index, new Val(temp, TYPE_COUNT));

		Unref(index);
		}

	return sessionIDTable;
	}


//--- SSL_InterpreterEndpoint -------------------------------------------------

/*!
 * The constructor.
 *
 * \param interpreter Pointer to the instance of an SSL_Interpreter to which
 *                    this endpoint belongs to.
 * \param is_orig true if this endpoint is the originator of the connection,
 *                false otherwise
 * SC: an adjustment was made here since the endpoints are now assosciated with
 * TCP_Contents base objects rather than TCP_Endpoint.
 */
SSL_InterpreterEndpoint::SSL_InterpreterEndpoint(SSL_Interpreter* arg_interpreter,
							bool arg_is_orig )
	{
	interpreter = arg_interpreter;
	is_orig = arg_is_orig;
	proxyEndpoint = new Contents_SSL(interpreter->Proxy()->Conn(), is_orig);
	ourProxyEndpoint = true;
	}

/*!
 * The destructor.
 */
SSL_InterpreterEndpoint::~SSL_InterpreterEndpoint()
	{
	SetProxyEndpoint(0);
	}

/*!
 * \return true if there's currently data pending for this endpoint,
 *         false otherwise
 */
bool SSL_InterpreterEndpoint::isDataPending()
	{
	return proxyEndpoint->isDataPending();
	}

/*!
 * Sets the peer of this endpoint.
 *
 * \param p Pointer to an interpreter endpoint which will be set as the peer
 *          of this endpoint.
 */
void SSL_InterpreterEndpoint::SetPeer(SSL_InterpreterEndpoint* p)
	{
	peer = p;
	}

/*!
 * Sets the proxy endpoint of this endpoint.
 *
 * \param p Pointer to a Contents_SSL analyzer which will be set as the proxy endpoint
 *          of this endpoint.
 */
void SSL_InterpreterEndpoint::SetProxyEndpoint(Contents_SSL* p)
	{
	if ( ourProxyEndpoint )
		{
		proxyEndpoint->Done();
		delete proxyEndpoint;
		ourProxyEndpoint = false;
		}

	proxyEndpoint = p;
	}

/*!
 * \return is_orig true if this endpoint is the originator of the connection,
 *                 false otherwise
 */
int SSL_InterpreterEndpoint::IsOrig() const
	{
	return is_orig;
	}

/*!
 * \return the peer of this endpoint
 */
SSL_InterpreterEndpoint* SSL_InterpreterEndpoint::Peer() const
	{
	return peer;
	}

/*!
 * \return the interpreter of this endpoint
 */
SSL_Interpreter* SSL_InterpreterEndpoint::Interpreter() const
	{
	return interpreter;
	}

// --- CertStore --------------------------------------------------------------

/*
 * The constructor.
 *
 * \param ip ip adress where this certificate came from
 * \param port port number where this certificate came from
 * \param hash hahssum for this certificate
 * \param size of this certificate in bytes
 */
CertStore::CertStore(uint32 ip, uint32 arg_port, hash_t hash, int size)
	{
	ip_addr = ip;
	certHash = hash;
	certSize = size;
	isValid = -1;
	changes = 0;
	port = arg_port;
	}

/*
 * This method can be used to compare certificates by certain criterias.
 *
 * \param hash hashsum of the certificate to compare
 * \param size size of the certificate to compare
 *
 * \return true if the criterias match, false otherwise
 */
bool CertStore::isSameCert(hash_t hash, int length)
	{
	return hash == certHash && length == certSize;
	}
