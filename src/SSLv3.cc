// $Id: SSLv3.cc 5988 2008-07-19 07:02:12Z vern $

#include "SSLv3.h"
#include "SSLCiphers.h"

// --- Initalization of static variables --------------------------------------

bool SSLv3_Interpreter::bInited = false;

uint SSLv3_Interpreter::totalConnections = 0;
uint SSLv3_Interpreter::openedConnections = 0;
uint SSLv3_Interpreter::totalRecords = 0;
uint SSLv3_Interpreter::handshakeRecords = 0;
uint SSLv3_Interpreter::clientHelloRecords = 0;
uint SSLv3_Interpreter::serverHelloRecords = 0;
uint SSLv3_Interpreter::alertRecords = 0;
uint SSLv3_Interpreter::changeCipherRecords = 0;


// ---SSLv3_Interpreter--------------------------------------------------------

// Initialize static:
SSLv3_Automaton SSLv3_Interpreter::sslAutomaton(SSL3_1_NUM_STATES,
					SSL3_1_NUM_TRANS, SSL3_1_STATE_ERROR);

SSLv3_Interpreter::SSLv3_Interpreter(SSLProxy_Analyzer* proxy)
: SSL_Interpreter(proxy)
	{
	pCipherSuite = 0;
	cipherSuiteIdentifier = 0;
	pClientCipherSpecs = 0;
	clientSessionID = 0;
	serverSessionID = 0;
	clientRandom = 0;
	serverRandom = 0;
	serverRSApars = 0;
	serverDHPars = 0;
	encryptedPreSecret = 0;
	clientDHpublic = 0;
	// keyXAlgorithm = SSL_KEY_EXCHANGE_NULL;
	change_cipher_client_seen = false;
	change_cipher_server_seen = false;
	fin_client_seen = false;
	fin_server_seen = false;
	helloRequestValid = true;

	if ( ! bInited )
		{
		BuildAutomaton();
		// BuildCipherDict();
		bInited = true;
		}

	currentState = SSL3_1_STATE_INIT;
	++totalConnections;
	}

SSLv3_Interpreter::~SSLv3_Interpreter()
	{
	delete pClientCipherSpecs;
	delete clientSessionID;
	delete serverSessionID;

	if ( ssl_store_key_material )
		{
		if ( clientRandom )
			delete clientRandom->random_bytes;
		delete clientRandom;
		if ( serverRandom )
			delete serverRandom->random_bytes;
		delete serverRandom;
		delete serverRSApars;
		delete serverDHPars;
		delete encryptedPreSecret;
		delete clientDHpublic;
		}
	}

void SSLv3_Interpreter::BuildInterpreterEndpoints()
	{
	orig = new SSLv3_Endpoint(this, 1);
	resp = new SSLv3_Endpoint(this, 0);
	}

void SSLv3_Interpreter::BuildAutomaton()
	{
	sslAutomaton.addTrans(SSL3_1_STATE_INIT, SSL3_1_TRANS_SERVER_HELLO_REQ,
		SSL3_1_STATE_SERVER_HELLO_REQ_SENT);

	sslAutomaton.addTrans(SSL3_1_STATE_SERVER_HELLO_REQ_SENT,
		SSL3_1_TRANS_CLIENT_HELLO, SSL3_1_STATE_CLIENT_HELLO_SENT);

	sslAutomaton.addTrans(SSL3_1_STATE_INIT, SSL3_1_TRANS_CLIENT_HELLO,
		SSL3_1_STATE_CLIENT_HELLO_SENT);

	sslAutomaton.addTrans(SSL3_1_STATE_CLIENT_HELLO_SENT,
		SSL3_1_TRANS_SERVER_HELLO, SSL3_1_STATE_SERVER_HELLO_SENT);

	sslAutomaton.addTrans(SSL3_1_STATE_SERVER_HELLO_SENT,
		SSL3_1_TRANS_SERVER_CERT, SSL3_1_STATE_SERVER_CERT_SENT);

	sslAutomaton.addTrans(SSL3_1_STATE_SERVER_HELLO_SENT,
		SSL3_1_TRANS_SERVER_KEY_EXCHANGE,
		SSL3_1_STATE_SERVER_KEY_EXCHANGE_SENT);

	// Server key-exchange and/or server requests cert from client.
	sslAutomaton.addTrans(SSL3_1_STATE_SERVER_CERT_SENT,
		SSL3_1_TRANS_SERVER_KEY_EXCHANGE,
		SSL3_1_STATE_SERVER_KEY_EXCHANGE_SENT);

	sslAutomaton.addTrans(SSL3_1_STATE_SERVER_KEY_EXCHANGE_SENT,
		SSL3_1_TRANS_SERVER_HELLO_DONE,
		SSL3_1_STATE_SERVER_HELLO_DONE_SENT_A);

	sslAutomaton.addTrans(SSL3_1_STATE_SERVER_KEY_EXCHANGE_SENT,
		SSL3_1_TRANS_SERVER_CERT_REQ,
		SSL3_1_STATE_SERVER_CERT_REQ_SENT);

	sslAutomaton.addTrans(SSL3_1_STATE_SERVER_CERT_SENT,
		SSL3_1_TRANS_SERVER_CERT_REQ,
		SSL3_1_STATE_SERVER_CERT_REQ_SENT);

	sslAutomaton.addTrans(SSL3_1_STATE_SERVER_CERT_REQ_SENT,
		SSL3_1_TRANS_SERVER_HELLO_DONE,
		SSL3_1_STATE_SERVER_HELLO_DONE_SENT_B);

	sslAutomaton.addTrans(SSL3_1_STATE_SERVER_HELLO_DONE_SENT_B,
		SSL3_1_TRANS_CLIENT_CERT, SSL3_1_STATE_CLIENT_CERT_SENT);

	sslAutomaton.addTrans(SSL3_1_STATE_CLIENT_CERT_SENT,
		SSL3_1_TRANS_CLIENT_KEY_EXCHANGE,
		SSL3_1_STATE_CLIENT_KEY_EXCHANGE_SENT_B);

	sslAutomaton.addTrans(SSL3_1_STATE_CLIENT_KEY_EXCHANGE_SENT_B,
		SSL3_1_TRANS_CLIENT_CERT_VERIFY,
		SSL3_1_STATE_CLIENT_CERT_VERIFY_SENT);

	sslAutomaton.addTrans(SSL3_1_STATE_CLIENT_KEY_EXCHANGE_SENT_B,
		SSL3_1_TRANS_CLIENT_FIN, SSL3_1_STATE_CLIENT_FIN_SENT_A);

	sslAutomaton.addTrans(SSL3_1_STATE_CLIENT_CERT_VERIFY_SENT,
		SSL3_1_TRANS_CLIENT_FIN, SSL3_1_STATE_CLIENT_FIN_SENT_A);

	sslAutomaton.addTrans(SSL3_1_STATE_CLIENT_FIN_SENT_A,
		SSL3_1_TRANS_SERVER_FIN, SSL3_1_STATE_HS_FIN_A);

	sslAutomaton.addTrans(SSL3_1_STATE_CLIENT_KEY_EXCHANGE_SENT_B,
		SSL3_1_TRANS_SERVER_FIN, SSL3_1_STATE_SERVER_FIN_SENT_A);

	sslAutomaton.addTrans(SSL3_1_STATE_CLIENT_CERT_VERIFY_SENT,
		SSL3_1_TRANS_SERVER_FIN, SSL3_1_STATE_SERVER_FIN_SENT_A);

	sslAutomaton.addTrans(SSL3_1_STATE_SERVER_FIN_SENT_A,
		SSL3_1_TRANS_CLIENT_FIN, SSL3_1_STATE_HS_FIN_A);

	// Server hello done after server cert sent.
	sslAutomaton.addTrans(SSL3_1_STATE_SERVER_CERT_SENT,
		SSL3_1_TRANS_SERVER_HELLO_DONE,
		SSL3_1_STATE_SERVER_HELLO_DONE_SENT_A);

	sslAutomaton.addTrans(SSL3_1_STATE_SERVER_HELLO_DONE_SENT_A,
		SSL3_1_TRANS_CLIENT_KEY_EXCHANGE,
		SSL3_1_STATE_CLIENT_KEY_EXCHANGE_SENT_A);

	sslAutomaton.addTrans(SSL3_1_STATE_CLIENT_KEY_EXCHANGE_SENT_A,
		SSL3_1_TRANS_CLIENT_FIN, SSL3_1_STATE_CLIENT_FIN_SENT_A);

	sslAutomaton.addTrans(SSL3_1_STATE_CLIENT_KEY_EXCHANGE_SENT_A,
		SSL3_1_TRANS_SERVER_FIN, SSL3_1_STATE_SERVER_FIN_SENT_A);

	sslAutomaton.addTrans(SSL3_1_STATE_CLIENT_FIN_SENT_A,
		SSL3_1_TRANS_SERVER_FIN, SSL3_1_STATE_HS_FIN_A);

	sslAutomaton.addTrans(SSL3_1_STATE_SERVER_FIN_SENT_A,
		SSL3_1_TRANS_CLIENT_FIN, SSL3_1_STATE_HS_FIN_A);

	// When reestablishing a session:
	sslAutomaton.addTrans(SSL3_1_STATE_SERVER_HELLO_SENT,
		SSL3_1_TRANS_CLIENT_FIN, SSL3_1_STATE_CLIENT_FIN_SENT_B);

	sslAutomaton.addTrans(SSL3_1_STATE_SERVER_HELLO_SENT,
		SSL3_1_TRANS_SERVER_FIN, SSL3_1_STATE_SERVER_FIN_SENT_B);

	sslAutomaton.addTrans(SSL3_1_STATE_CLIENT_FIN_SENT_B,
		SSL3_1_TRANS_SERVER_FIN, SSL3_1_STATE_HS_FIN_B);

	sslAutomaton.addTrans(SSL3_1_STATE_SERVER_FIN_SENT_B,
		SSL3_1_TRANS_CLIENT_FIN, SSL3_1_STATE_HS_FIN_B);

	sslAutomaton.setStartState(SSL3_1_STATE_INIT);
	}

void SSLv3_Interpreter::printStats()
	{
	printf( "SSLv3x:\n" );
	printf( "Note: Because handshake messages may be coalesced into a \n");
	printf( "      single SSLv3x record, the number of total messages for SSLv3x plus \n");
	printf( "      the number of total records seen for SSLv2 won't match \n");
	printf( "      SSLProxy_Analyzer::totalRecords! \n");
	printf( "total connections			= %u\n", totalConnections );
	printf( "opened connections (complete handshake)	= %u\n", openedConnections );

	printf( "total messages seen			= %u\n", totalRecords );
	printf( "handshake messages seen			= %u\n", handshakeRecords );
	printf( "alert records seen			= %u\n", alertRecords );
	printf( "change cipher records seen		= %u\n", changeCipherRecords );
	printf( "client hello messages seen		= %u\n", clientHelloRecords );
	printf( "server hello messages seen		= %u\n", serverHelloRecords );
	}

int SSLv3_Interpreter::HandshakeType2Trans(int type)
	{
	switch ( SSL3_1_HandshakeType(type) ) {
	case SSL3_1_HELLO_REQUEST: return SSL3_1_TRANS_SERVER_HELLO_REQ;
	case SSL3_1_CLIENT_HELLO: return SSL3_1_TRANS_CLIENT_HELLO;
	case SSL3_1_SERVER_HELLO: return SSL3_1_TRANS_SERVER_HELLO;

	case SSL3_1_CERTIFICATE:
		// Client- and server certificate handshake records lead
		// to the same transition in the SSL automaton
		// (see SSLDefines.h)
		return SSL3_1_TRANS_SERVER_CERT;

	case SSL3_1_SERVER_KEY_EXCHANGE: return SSL3_1_TRANS_SERVER_KEY_EXCHANGE;
	case SSL3_1_CERTIFICATE_REQUEST: return SSL3_1_TRANS_SERVER_CERT_REQ;
	case SSL3_1_SERVER_HELLO_DONE: return SSL3_1_TRANS_SERVER_HELLO_DONE;
	case SSL3_1_CERTIFICATE_VERIFY: return SSL3_1_TRANS_CLIENT_CERT_VERIFY;
	case SSL3_1_CLIENT_KEY_EXCHANGE: return SSL3_1_TRANS_CLIENT_KEY_EXCHANGE;

	case SSL3_1_FINISHED:
		// Client- and server certificate handshake records lead
		// to the same transition in the SSL automaton
		// (see SSLDefines.h)
		return SSL3_1_TRANS_CLIENT_FIN;
	default:
		return -1;
	}
	}

void SSLv3_Interpreter::DeliverSSLv3_Record(SSLv3_HandshakeRecord* rec)
	{
	++SSLv3_Interpreter::totalRecords;
	++SSLv3_Interpreter::handshakeRecords;

	TableVal* currentCipherSuites = 0;

	// First: consistency checks.
	// Special treatment for finished messages, because they are
	// already encrypted (encrypted handshake message).
	if ( (change_cipher_client_seen && (rec->endp)->IsOrig() &&
	      ! fin_client_seen) ||
	     (change_cipher_server_seen && ! rec->endp->IsOrig() &&
	      ! fin_server_seen) )
		{
		// no checks can be performed due encryption...
		}
	else
		{
		SSL3_1_HandshakeType ht = SSL3_1_HandshakeType(rec->type);
		switch ( ht ) {
		case SSL3_1_HELLO_REQUEST:
			if ( rec->length != 0 )
				Weird("SSLv3x: Hello request too long!");
			if ( ! helloRequestValid )
				Weird("SSLv3x: Received hello request during handshake!");
			// There should only be sent one hello request at a
			// time.
			helloRequestValid = false;
			break;

		case SSL3_1_CLIENT_HELLO:
			{
			++SSLv3_Interpreter::clientHelloRecords;

			// During the handshaking phase, we don't want any
			// more hello requests.
			helloRequestValid = false;

			if ( rec->checkClientHello() == 0 )
				return;

			const u_char* pTemp = rec->data;
			uint8 sessionIDLength = uint8(pTemp[38]);
			clientSessionID =
				new SSL_DataBlock((pTemp + 39), sessionIDLength);
			uint16 cipherSuiteLength =
				uint16(pTemp[39 + sessionIDLength] << 8 ) |
				pTemp[40 + sessionIDLength];

			currentCipherSuites =
				analyzeCiphers(rec->endp, cipherSuiteLength,
					rec->data + 41 + sessionIDLength,
					rec->sslVersion);

			if ( ssl_store_key_material )
				{
				clientRandom = new SSLv3x_Random();
				clientRandom->random_bytes = 0;
				clientRandom->gmt_unix_time =
					uint32(((pTemp[6] << 24) |
						pTemp[7] << 16) |
					       pTemp[8] << 8) | pTemp[9];

				clientRandom->random_bytes =
					new SSL_DataBlock(pTemp + 10, 28);
				}
			break;
			}

		case SSL3_1_SERVER_HELLO:
			{
			++SSLv3_Interpreter::serverHelloRecords;
			if ( rec->checkServerHello() == 0)
				return;

			const u_char* pTemp = rec->data;
			uint8 sessionIDLength = uint8(pTemp[38]);
			serverSessionID =
				new SSL_DataBlock(pTemp + 39, sessionIDLength);
			currentCipherSuites =
				analyzeCiphers(rec->endp, 2,
					rec->data + 39 + sessionIDLength,
					rec->sslVersion);

			// Check whether the cipher suite the server choose
			// was included in the cipher suites the client
			// anounced.
			if ( pClientCipherSpecs && pCipherSuite )
				{
				bool bFound = false;
				uint16 tempClientCipher;
				for ( int i = 0; i < pClientCipherSpecs->len;
				      i += 2 )
					{
					tempClientCipher =
						(pClientCipherSpecs->data[i] << 8) |
						pClientCipherSpecs->data[i+1];

					if ( tempClientCipher ==
					     pCipherSuite->identifier )
						{
						bFound = true;
						i = pClientCipherSpecs->len;
						}
					}

				if ( ! bFound )
					Weird("SSLv3x: Server choosed cipher spec that client didn't anounce!");

				delete pClientCipherSpecs;
				pClientCipherSpecs = 0;
				}

			if ( ssl_store_key_material )
				{
				serverRandom = new SSLv3x_Random();
				serverRandom->gmt_unix_time =
					uint32(((pTemp[6] << 8) |
						pTemp[7] << 8) |
					       pTemp[8] << 8) | pTemp[9];
				serverRandom->random_bytes =
					new SSL_DataBlock(pTemp + 10, 28);
				}

			// Insert session injection into here.

			if ( ! ssl_session_insertion )
				break; // in place of below

			TableVal* sessionIDTable =
				serverSessionID ?
					MakeSessionID(serverSessionID->data,
							serverSessionID->len) :
					MakeSessionID(0, 0);

			val_list* vl = new val_list;
			vl->append(proxy->BuildConnVal());
			vl->append(sessionIDTable);

			proxy->ConnectionEvent(ssl_session_insertion, vl);
			break;
			}

		case SSL3_1_CERTIFICATE:
			{
			if ( rec->length >= 3 )
				{
				const u_char* pData = rec->data;
				uint32 certListLength =
					uint32((pData[4] << 16) |
					       pData[5] << 8) | pData[6];

				// Size consistency checks.
				if ( certListLength + 3 != uint32(rec->length) )
					{
					if ( rec->endp->IsOrig() )
						Weird("SSLv3x: Corrupt length field in client certificate list!");
					else
						Weird("SSLv3x: Corrupt length field in server certificate list!");
					return;
					}

				// Sum of all cert sizes has to match
				// certListLength.
				uint tempLength = 0;
				uint certCount = 0;
				while ( tempLength < certListLength )
					{
					if ( tempLength + 3 <= certListLength )
						{
						++certCount;
						uint32 certLength =
							uint32((pData[tempLength + 7] << 16) | pData[tempLength + 8] << 8) | pData[tempLength + 9];
						tempLength += certLength + 3;
						}
					else
						{
						Weird("SSLv3x: Corrupt length field in certificate list!");
						return;
						}
					}

				if ( tempLength > certListLength )
					{
					Weird("SSLv3x: sum of size of certificates doesn't match size of certificate chain");
					return;
					}

				SSL_InterpreterEndpoint* pEp =
					(SSL_InterpreterEndpoint*) rec->endp;

				if ( certCount == 0 )
					{ // we don't have a certificate...
					if ( rec->endp->IsOrig() )
						{
						Weird("SSLv3x: Client certificate is missing!");
						break;
						}
					else
						{
						Weird("SSLv3x: Server certificate is missing!");
						break;
						}
					}

				if ( certCount > 1 )
					{ // we have a chain
					analyzeCertificate(pEp,
						rec->data + 7,
						certListLength, 1, true);
					}
				else
					{
					// We have a single certificate.
					// FIXME.
					analyzeCertificate(pEp,
						rec->data + 10,
						certListLength-3, 1, false);
					}

				}
			else
				Weird("SSLv3x: Certificate record too small!" );
			break;
			}

		case SSL3_1_SERVER_KEY_EXCHANGE:
			{
			/*
			switch (cipherSuite)
				{
				// It would be necessary to have the RSA key length
				// out of the server's certificate. If the cipher suite
				// is EXPORT, than a RSA key length larger than 512 bits
				// is not allowed for encryption and thus, the server needs
				// to send a key-exchange-message in order to negotiate the
				// pre-master secret (see rfc 2246 page 39)
				case TLS_RSA_WITH_NULL_MD5:
				case TLS_RSA_WITH_NULL_SHA:
				// case TLS_RSA_EXPORT_WITH_RC4_40_MD5: //see comment above
				case TLS_RSA_WITH_RC4_128_MD5:
				case TLS_RSA_WITH_RC4_128_SHA:
				// case TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5: //see comment above
				case TLS_RSA_WITH_IDEA_CBC_SHA:
				// case TLS_RSA_EXPORT_WITH_DES40_CBC_SHA: //see comment above
				case TLS_RSA_WITH_DES_CBC_SHA:
				case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
				case TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA:
				case TLS_DH_DSS_WITH_DES_CBC_SHA:
				case TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
				case TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA:
				case TLS_DH_RSA_WITH_DES_CBC_SHA:
				case TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
					{
					Weird("SSLv3x: Sending server-key-exchange not allowed for this cipher suite!");
					return;
					break;
					}
				default:
					break;
				}
			*/

			if ( ! pCipherSuite )
				// If we have an unknown CIPHER-SPEC,
				// we can't do our weird checks.
				break;

			SSL_KeyExchangeAlgorithm keyXAlgorithm =
				pCipherSuite->keyExchangeAlgorithm;

			if ( keyXAlgorithm == SSL_KEY_EXCHANGE_RSA ||
			     keyXAlgorithm == SSL_KEY_EXCHANGE_DH_DSS ||
			     keyXAlgorithm == SSL_KEY_EXCHANGE_DH_RSA )
				{
				Weird("SSLv3x: Sending server-key-exchange not allowed for this cipher suite!");
				return;

				}
			// FIXME: check where DHE_RSA etc. belongs to
			const u_char* pTemp = rec->data;
			if ( ssl_store_key_material )
				{
				if ( keyXAlgorithm == SSL_KEY_EXCHANGE_RSA ||
				     keyXAlgorithm == SSL_KEY_EXCHANGE_RSA ||
				     keyXAlgorithm == SSL_KEY_EXCHANGE_RSA_EXPORT1024 )
					{ // some weird checks
					if ( rec->length < 2 )
						{
						Weird("SSLv3x: server-key-exchange empty!");
						return;
						}

					uint16 modulusLength = uint16(pTemp[4] << 8 ) | pTemp[5];
					if ( modulusLength + 4 > rec->length )
						{
						Weird("SSLv3x: Corrupt length fields in server-key-exchange!");
						break;
						}

					uint16 exponentLength = uint16(pTemp[6 + modulusLength] << 8 ) | pTemp[7 + modulusLength];
					if ( modulusLength + exponentLength + 4 > rec->length )
						{
						Weird("SSLv3x: Corrupt length fields in server-key-exchange!");
						return;
						}

					serverRSApars =
						new SSLv3x_ServerRSAParams;
					serverRSApars->rsa_modulus =
						new SSL_DataBlock(pTemp + 6, modulusLength);
					serverRSApars->rsa_exponent =
						new SSL_DataBlock( pTemp + 8 + modulusLength, exponentLength);
					}
				else
					{
					if ( keyXAlgorithm == SSL_KEY_EXCHANGE_DH || keyXAlgorithm == SSL_KEY_EXCHANGE_DH_DSS || keyXAlgorithm == SSL_KEY_EXCHANGE_DH_DSS_EXPORT || keyXAlgorithm == SSL_KEY_EXCHANGE_DH_RSA || keyXAlgorithm == SSL_KEY_EXCHANGE_DH_RSA_EXPORT || keyXAlgorithm == SSL_KEY_EXCHANGE_DHE_DSS || keyXAlgorithm == SSL_KEY_EXCHANGE_DHE_DSS_EXPORT || keyXAlgorithm == SSL_KEY_EXCHANGE_DHE_RSA || keyXAlgorithm == SSL_KEY_EXCHANGE_DHE_RSA_EXPORT || keyXAlgorithm == SSL_KEY_EXCHANGE_DH_ANON || keyXAlgorithm == SSL_KEY_EXCHANGE_DH_ANON_EXPORT || keyXAlgorithm == SSL_KEY_EXCHANGE_DHE_DSS_EXPORT1024 )
						{
						if ( rec->length < 2 )
							{
							Weird("SSLv3x: server-key-exchange empty!");
							return;
							}

						uint16 dh_pLength = (uint16) (pTemp[4] << 8 ) | pTemp[5];
						if ( dh_pLength + 4 > rec->length )
							{
							Weird("SSLv3x: Corrupt length fields in server-key-exchange!");
							break;
							}

						uint16 dh_gLength = uint16(pTemp[6 + dh_pLength] << 8 ) | pTemp[7 + dh_pLength];
						uint16 dh_YsLength = uint16(pTemp[8 + dh_pLength + dh_gLength] << 8 ) | pTemp[9 + dh_pLength + dh_gLength];
						if ( dh_pLength + dh_gLength + dh_YsLength + 6 > rec->length )
							{
							Weird("SSLv3x: Corrupt length fields in server-key-exchange!");
							printf("xxx %u > %u \n", (dh_pLength + dh_gLength + dh_YsLength + 6), rec->length);
							return;
							}

						serverDHPars = new SSLv3x_ServerDHParams;
						serverDHPars->dh_p = new SSL_DataBlock(pTemp + 6 , dh_pLength);
						serverDHPars->dh_g = new SSL_DataBlock(pTemp + 8 + dh_pLength, dh_gLength);
						serverDHPars->dh_Ys = new SSL_DataBlock(pTemp + 10 + dh_pLength + dh_gLength, dh_YsLength);
						}
					}
				}
			break;
			}

		case SSL3_1_CERTIFICATE_REQUEST:
			{
			// Only if server not anonymous
			/*
			switch (cipherSuite)
				{
				case TLS_NULL_WITH_NULL_NULL:
				case TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5:
				case TLS_DH_ANON_WITH_RC4_128_MD5:
				case TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA:
				case TLS_DH_ANON_WITH_DES_CBC_SHA:
				case TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA:
					{
					Weird("SSLv3x: Sending certificate-request not allowed for anonymous servers!");
					break;
					}
				default:
					{
					break;
					}
				}
			*/

			if ( ! pCipherSuite )
				{
				// if we have an unknown CIPHER-SPEC,
				// we can't do our weird checks.
				break;
				}

			if ( pCipherSuite->keyExchangeAlgorithm == SSL_KEY_EXCHANGE_DH_ANON || pCipherSuite->keyExchangeAlgorithm == SSL_KEY_EXCHANGE_DH_ANON_EXPORT )
				Weird("SSLv3x: Sending certificate-request not allowed for anonymous servers!");

			// FIXME: Insert weird checks!
			break;
			}

		case SSL3_1_SERVER_HELLO_DONE:
			{
			if ( rec->length != 0 )
				Weird("SSLv3x: Server hello too long!");
			break;
			}

		case SSL3_1_CLIENT_KEY_EXCHANGE:
			{
			if ( ! pCipherSuite )
				// if we have an unknown CIPHER-SPEC,
				// we can't do our weird checks
				break;

			const u_char* pTemp = rec->data;
			if ( ssl_store_key_material )
				{
				SSL_KeyExchangeAlgorithm keyXAlgorithm =
					pCipherSuite->keyExchangeAlgorithm;

				if ( keyXAlgorithm == SSL_KEY_EXCHANGE_RSA || keyXAlgorithm == SSL_KEY_EXCHANGE_DH_DSS || keyXAlgorithm == SSL_KEY_EXCHANGE_DH_RSA )
					{
					encryptedPreSecret =
						new SSLv3x_EncryptedPremasterSecret;
					encryptedPreSecret->encryptedSecret =
						new SSL_DataBlock( pTemp + 4, rec->length);
					}
				else
					{
					if ( keyXAlgorithm == SSL_KEY_EXCHANGE_DH || keyXAlgorithm == SSL_KEY_EXCHANGE_DH_DSS || keyXAlgorithm == SSL_KEY_EXCHANGE_DH_DSS_EXPORT || keyXAlgorithm == SSL_KEY_EXCHANGE_DH_RSA || keyXAlgorithm == SSL_KEY_EXCHANGE_DH_RSA_EXPORT || keyXAlgorithm == SSL_KEY_EXCHANGE_DHE_DSS || keyXAlgorithm == SSL_KEY_EXCHANGE_DHE_DSS_EXPORT || keyXAlgorithm == SSL_KEY_EXCHANGE_DHE_RSA || keyXAlgorithm == SSL_KEY_EXCHANGE_DHE_RSA_EXPORT || keyXAlgorithm == SSL_KEY_EXCHANGE_DH_ANON || keyXAlgorithm == SSL_KEY_EXCHANGE_DH_ANON_EXPORT || keyXAlgorithm == SSL_KEY_EXCHANGE_DHE_DSS_EXPORT1024 )
						{
						if ( rec->length < 2 )
							{
							// This can happen (see RFC 2246, p. 45).
							return;
							}

						uint16 DHpublicLength =
							uint16(pTemp[4] << 8) | pTemp[5];
						if ( DHpublicLength + 2 < rec->length )
							{
							Weird("SSLv3x: Corrupt length fields in client-key-exchange!");
							return;
							}

						clientDHpublic = new SSLv3x_ClientDHPublic;
						clientDHpublic->dh_Yc = new SSL_DataBlock(pTemp + 6, DHpublicLength);
						}
					}

				}
			break;
			}

		case SSL3_1_CERTIFICATE_VERIFY:
			{
			// FIXME: Insert Weird checks!
			break;
			}

		case SSL3_1_FINISHED:
			{
			// We won't get here, because finished messages
			// are already encrypted, so we can't get
			// the content type of this handshake-message...
			break;
			}

		default:
			{
			if ( currentState == SSL3_1_STATE_SERVER_FIN_SENT_A ||
			     currentState == SSL3_1_STATE_CLIENT_FIN_SENT_B )
				{
				Weird("SSLv3x: Handshake message (unknown type) after finished message!");
				return;
				}
			else
				{
				Weird("SSLv3x: Invalid HandshakeType! Maybe finished message without predecessing change-cipher-message!");
				return; }
			}
		}
		}

	int oldState = currentState;
	bool alreadySwitchedState = false;

	// First: Special handling of finished messages. They must be
	// sent immediately after a change cipher message - already encrypted.
	// from client?
	if ( rec->endp->IsOrig() && change_cipher_client_seen )
		{
		if ( ! fin_client_seen )
			{
			// This must be a (valid) client finished.
			// We assume it to be one, because the predecessing
			// message was a change cipher.
			fin_client_seen = true;
			change_cipher_client_seen = false;
			alreadySwitchedState = true;
			currentState = sslAutomaton.getNextState(currentState,
						SSL3_1_TRANS_CLIENT_FIN);
			}
		else
			{
			// We already saw a client finished (should not be
			// possible).
			Weird("SSLv3x: Already received client finished message!");
			currentState = sslAutomaton.getNextState(currentState,
						SSL3_1_TRANS_CLIENT_FIN);
			fin_client_seen = true;
			change_cipher_client_seen = false;
			alreadySwitchedState = true;
			}
		}

	// from server
	else if ( ! rec->endp->IsOrig() && change_cipher_server_seen )
		{
		if ( ! fin_server_seen )
			{
			// This must be a (valid) server finished.
			// We assume it to be one, because the predecessing
			// message was a change cipher.
			fin_server_seen = true;
			change_cipher_server_seen = false;
			alreadySwitchedState = true;
			currentState = sslAutomaton.getNextState(currentState,
				SSL3_1_TRANS_SERVER_FIN);
			}
		else
			{
			// We already saw a server-finished (should not be
			// possible).
			Weird("SSLv3x: Already received server finished message!");
			currentState = sslAutomaton.getNextState(currentState,
						SSL3_1_TRANS_SERVER_FIN);
			alreadySwitchedState = true;
			fin_server_seen = true;
			change_cipher_server_seen = false;
			}
		}

	if ( ! alreadySwitchedState )
		{
		// Check whether we are already finished with the
		// handshaking process...
		switch ( currentState ) {
		case SSL3_1_STATE_HS_FIN_A:
		case SSL3_1_STATE_HS_FIN_B:
			Weird("SSLv3x: Received handshake message after finishing handshake!");
			break;

		default:
			// It's a "normal" handshake message...
			currentState = sslAutomaton.getNextState(currentState,
				HandshakeType2Trans(rec->type));
			break;
		}
		}

	if ( currentState == SSL3_1_STATE_ERROR )
		{
		// proxy->SetSkip(1);
		}

	// Only if we changed the currentState, we need to call GenerateEvents
	// because event generation in GenerateEvents() is based on
	// currentState.
	if ( oldState != currentState )
		GenerateEvents(rec, currentCipherSuites);
	else
		Unref(currentCipherSuites);
	}

void SSLv3_Interpreter::DeliverSSLv3_Record(SSLv3_AlertRecord* rec)
	{
	++SSLv3_Interpreter::totalRecords;
	++SSLv3_Interpreter::alertRecords;

	// First: consistency-checks.
	// Only if handshake not already finished.
	// Otherwise alerts may be encrypted, so we could do nothing...
	if ( currentState == SSL3_1_STATE_SERVER_FIN_SENT_A ||
	     currentState == SSL3_1_STATE_CLIENT_FIN_SENT_B ||
	     currentState == SSL3_1_STATE_CLIENT_FIN_SENT_A ||
	     currentState == SSL3_1_STATE_SERVER_FIN_SENT_B ||
	     currentState == SSL3_1_STATE_HS_FIN_A ||
	     currentState == SSL3_1_STATE_HS_FIN_B ||
	     change_cipher_client_seen || change_cipher_server_seen )
		return;

	if ( rec->level != SSL3x_ALERT_LEVEL_WARNING &&
	     rec->level != SSL3x_ALERT_LEVEL_FATAL )
		Weird("SSLv3x: Unknown ssl alert level");

	SSL3_1_AlertDescription ad = SSL3_1_AlertDescription(rec->description);
	switch ( ad ) {
	case SSL3_1_CLOSE_NOTIFY:
	case SSL3_1_UNEXPECTED_MESSAGE:
	case SSL3_1_BAD_RECORD_MAC:
	case SSL3_1_DECRYPTION_FAILED:
	case SSL3_1_RECORD_OVERFLOW:
	case SSL3_1_DECOMPRESSION_FAILURE:
	case SSL3_1_HANDSHAKE_FAILURE:
		break;

	case SSL3_0_NO_CERTIFICATE:
		// This may happen ONLY in SSLv3.0 when the server sends
		// a certificate request but the client has none.
		if ( rec->sslVersion == SSLProxy_Analyzer::SSLv30 )
			currentState = SSL3_1_STATE_SERVER_HELLO_DONE_SENT_A;
		else
			Weird("SSLv3x: No certificate alert not defined for SSL 3.1!");
		break;

	case SSL3_1_BAD_CERTIFICATE:
	case SSL3_1_UNSUPPORTED_CERTIFICATE:
	case SSL3_1_CERTIFICATE_REVOKED:
	case SSL3_1_CERTIFICATE_EXPIRED:
	case SSL3_1_CERTIFICATE_UNKNOWN:
	case SSL3_1_ILLEGAL_PARAMETER:
	case SSL3_1_UNKNOWN_CA:
	case SSL3_1_ACCESS_DENIED:
	case SSL3_1_DECODE_ERROR:
	case SSL3_1_DECRYPT_ERROR:
	case SSL3_1_EXPORT_RESTRICTION:
	case SSL3_1_PROTOCOL_VERSION:
	case SSL3_1_INSUFFICIENT_SECURITY:
	case SSL3_1_INTERNAL_ERROR:
	case SSL3_1_USER_CANCELED:
	case SSL3_1_NO_RENEGOTIATION:
		break;

	default:
		Weird(" SSLv3x: Unknown ssl alert description!" );
		break;
	}

	if ( rec->level == 2 )
		// Fatal alert!
		currentState = SSL3_1_STATE_INIT;

	if ( rec->level == 1 && ad == SSL3_1_CLOSE_NOTIFY )
		currentState = SSL3_1_STATE_INIT;

	fire_ssl_conn_alert(rec->sslVersion, rec->level, rec->description);
	}

void SSLv3_Interpreter::DeliverSSLv3_Record(SSLv3_ChangeCipherRecord* rec)
	{
	++SSLv3_Interpreter::totalRecords;
	++SSLv3_Interpreter::changeCipherRecords;

	if ( rec->type != 1 )
		Weird("SSLv3x: Unknown change cipher type!");
	if ( rec->recordLength != 1 )
		Weird("SSLv3x: Change cipher message too long!");

	// After receiving a change cipher spec message, the next message sent
	// MUST be a finished message. So we set the appropriate flag:
	// change_cipher_client/server_seen.
	if ( rec->endp->IsOrig())
		{
		if ( change_cipher_client_seen )
			Weird("SSLv3x: Received multiple change cipher message from client!");
		change_cipher_client_seen = true;
		fin_client_seen = false;
		}
	else
		{
		if ( change_cipher_server_seen )
			Weird("SSLv3x: Received multiple change cipher message from server!");
		change_cipher_server_seen = true;
		fin_server_seen = false;
		}

	if ( currentState == SSL3_1_STATE_ERROR )
		{
		// proxy->SetSkip(1);
		}

	// We don't need a GenerateEvents here, because we didn't change
	// the currentState of the SSL automaton.  (Event generation
	// in GenerateEvents() is done based on currentState.)
	// GenerateEvents(rec);
	}

void SSLv3_Interpreter::DeliverSSLv3_Record(SSLv3_ApplicationRecord* rec)
	{
	++SSLv3_Interpreter::totalRecords;

	if ( currentState == SSL3_1_STATE_HS_FIN_A ||
	     currentState == SSL3_1_STATE_HS_FIN_B )
		// O.K., sending application data is valid
		// this was the last record we analyzed...
		proxy->SetSkip(1);
	else
		{
		// Sending application data now is not valid, so the SSL
		// connection is probably already established and we
		// didn't get the handshake.
		Weird("SSLv3_data_without_full_handshake");
		currentState = SSL3_1_STATE_ERROR;
		GenerateEvents(rec, 0);
		}
	}

TableVal* SSLv3_Interpreter::analyzeCiphers(const SSLv3_Endpoint* s, int length,
					const u_char* data, uint16 version)
	{
	int is_orig = (SSL_InterpreterEndpoint*) s == orig;

	if ( length > ssl_max_cipherspec_size )
		{
		if ( is_orig )
			Weird("SSLv2: Client has CipherSpecs > ssl_max_cipherspec_size");
		else
			Weird("SSLv2: Server has CipherSpecs > ssl_max_cipherspec_size");
		}

	const u_char* pCipher = data;
	SSL_CipherSpec* pCipherSuiteTemp = 0;
	uint16 cipherSuite;
	for ( int i = 0; i < length; i += 2 )
		{
		cipherSuite = uint16(pCipher[0+i] << 8) | pCipher[1+i];
		HashKey h(static_cast<bro_uint_t>(cipherSuite));

		pCipherSuiteTemp =
			(SSL_CipherSpec*) SSL_CipherSpecDict.Lookup(&h);
		if ( ! pCipherSuiteTemp )
			{
			if ( is_orig )
				proxy->Weird("SSLv3x: Unknown CIPHER-SPEC in CLIENT-HELLO");
			else
				proxy->Weird("SSLv3x: Unknown CIPHER-SPEC in SERVER-HELLO");
			}
		}

	// Store server's cipher specs.
	if ( ! is_orig )
		{
		pCipherSuite = pCipherSuiteTemp;
		if ( ! pCipherSuite )
			{
			// Special case: we store the identifier directly
			// for unknown cipher-specs.
			cipherSuiteIdentifier =
				uint16(pCipher[0] << 8) | pCipher[1];
			}
		}

	if ( ssl_compare_cipherspecs && length <= ssl_max_cipherspec_size )
		{
		// Store cipher specs for analysis: was the choosen
		// server cipher suite announced by the client?
		if ( is_orig )
			{
			pClientCipherSpecs =
				new SSL_DataBlock(data, length);
			}
		}

	if ( (! is_orig && ssl_conn_server_reply) ||
	     (is_orig && ssl_conn_attempt) )
		{
		TableVal* pCipherTable = new TableVal(cipher_suites_list);
		for ( int i = 0; i < length; i += 2 )
			{
			uint32 cipherSpec = (pCipher[0] << 8) | pCipher[1];
			Val* index = new Val(cipherSpec, TYPE_COUNT);
			pCipherTable->Assign(index, 0);
			Unref(index);
			pCipher += 2;
			}

		return pCipherTable;
		}

	else
		return 0;
	}

void SSLv3_Interpreter::GenerateEvents(SSLv3_Record* rec, TableVal* curCipherSuites)
	{
	if ( curCipherSuites &&
	     currentState != SSL3_1_STATE_CLIENT_HELLO_SENT &&
	     currentState != SSL3_1_STATE_SERVER_HELLO_SENT )
	        // Unref here, since the events won't do so in this case.
	        Unref(curCipherSuites);

	switch ( currentState ) {
	case SSL3_1_STATE_CLIENT_HELLO_SENT:
		fire_ssl_conn_attempt(rec->sslVersion, curCipherSuites);
		break;

	case SSL3_1_STATE_SERVER_HELLO_SENT:
		fire_ssl_conn_server_reply(rec->sslVersion, curCipherSuites);
		break;

	case SSL3_1_STATE_HS_FIN_A:
	case SSL3_1_STATE_HS_FIN_B:
		++SSLv3_Interpreter::openedConnections;
		fire_ssl_conn_established(rec->sslVersion,
					  pCipherSuite ?
						pCipherSuite->identifier : 0);

		// We finished handshake.  Skip all further data.
		proxy->SetSkip(1);
		helloRequestValid = true;
		break;

	case SSL3_1_STATE_SERVER_FIN_SENT_B:
		// First, check for session-ID match.
		if ( clientSessionID && serverSessionID &&
		     memcmp(clientSessionID->data, serverSessionID->data,
			    clientSessionID->len) != 0 )
			Weird("SSLv3x: Reusing session but session ID mismatch!");
		fire_ssl_conn_reused(serverSessionID);
		break;

	case SSL3_1_STATE_ERROR:
		Weird("unexpected_SSLv3_record");
		proxy->SetSkip(1);
	}
	}

void SSLv3_Interpreter::SetState(int i)
	{
	if ( i >= 0 && i < SSL3_1_NUM_STATES )
		currentState = i;
	}

// ---SSLv3_Endpoint--------------------------------------------------------------

SSLv3_Endpoint::SSLv3_Endpoint(SSL_Interpreter* interpreter, int is_orig)
: SSL_InterpreterEndpoint(interpreter, is_orig)
	{
	sslVersion = 0;
	}

SSLv3_Endpoint::~SSLv3_Endpoint()
	{
	}

void SSLv3_Endpoint::Deliver(int len, const u_char* data)
	{
	if ( SSL3_1_LENGTHOFFSET + sizeof(uint16) <= unsigned(len) )
		{
		currentMessage_length =
			uint16(data[SSL3_1_LENGTHOFFSET] << 8) |
			data[SSL3_1_LENGTHOFFSET+1];

		// ### where does this magic number come from?
		if ( currentMessage_length > 18432 )
			interpreter->Weird("SSLv3x: Message length too long!");
		}
	else
		{
		interpreter->Weird("SSLv3x: Could not determine message length!");
		return;
		}

	if ( currentMessage_length + 2 + SSL3_1_LENGTHOFFSET != len )
		{
		// This should never happen; otherwise there is a bug in the
		// SSL_RecordBuilder.
		interpreter->Weird("SSLv3x: FATAL: recordLength doesn't match data block length!");
		interpreter->Proxy()->SetSkip(1);
		return;
		}

	ProcessMessage(data, len);
	}

void SSLv3_Endpoint::ProcessMessage(const u_char* data, int len)
	{
	SSL3_1_ContentType ct = ExtractContentType(data, len);
	if ( ! ExtractVersion(data, len) )
		return;

	switch ( ct ) {
	case SSL3_1_TYPE_CHANGE_CIPHER_SPEC:
		{
		SSLv3_ChangeCipherRecord* rec = new
			SSLv3_ChangeCipherRecord(data + SSL3_1_HEADERLENGTH,
				len - SSL3_1_HEADERLENGTH, sslVersion, this);

		// Multiple handshake messages may be coalesced into
		// a single record.
		rec->Deliver((SSLv3_Interpreter*) interpreter);
		Unref(rec);
		break;
		}

	case SSL3_1_TYPE_ALERT:
		{
		SSLv3_AlertRecord* rec = new
			SSLv3_AlertRecord(data + SSL3_1_HEADERLENGTH,
				len - SSL3_1_HEADERLENGTH, sslVersion, this);
		rec->Deliver((SSLv3_Interpreter*) interpreter);
		Unref(rec);
		break;
		}

	case SSL3_1_TYPE_HANDSHAKE:
		{
		SSLv3_HandshakeRecord* rec =
			new SSLv3_HandshakeRecord(data + SSL3_1_HEADERLENGTH,
				len - SSL3_1_HEADERLENGTH, sslVersion, this);
		rec->Deliver((SSLv3_Interpreter*) interpreter);
		Unref(rec);
		break;
		}

	case SSL3_1_TYPE_APPLICATION_DATA:
		{
		SSLv3_ApplicationRecord* rec =
			new SSLv3_ApplicationRecord(data + SSL3_1_HEADERLENGTH,
				len - SSL3_1_HEADERLENGTH, sslVersion, this);
		rec->Deliver((SSLv3_Interpreter*) interpreter);
		Unref(rec);
		break;
		}

	default:
		{
		interpreter->Weird("SSLv3x: Could not determine content type!");
		break;
		}
	}
	}

SSL3_1_ContentType SSLv3_Endpoint::ExtractContentType(const u_char* data,
							int len)
	{
	return SSL3_1_ContentType(uint8(*(data + SSL3_1_CONTENTTYPEOFFSET)));
	}

int SSLv3_Endpoint::ExtractVersion(const u_char* data, int len)
	{
	sslVersion = uint16(data[SSL3_1_VERSIONTYPEOFFSET] << 8) |
		     data[SSL3_1_VERSIONTYPEOFFSET + 1];

	if ( sslVersion != SSLProxy_Analyzer::SSLv30 &&
	     sslVersion != SSLProxy_Analyzer::SSLv31 )
		{
		interpreter->Weird("SSLv3x: Unsupported SSL-Version (not SSLv3x)!");
		return 0;
		}
	else
		return 1;
	}

// ---SSLv3_Record----------------------------------------------------------------

SSLv3_Record::SSLv3_Record(const u_char* data, int len,
			uint16 version, SSLv3_Endpoint const* e)
	{
	recordLength = len;
	sslVersion = version;
	endp = e;
	this->data = data;
	}

SSLv3_Record::~SSLv3_Record()
	{
	// The memory for data is deleted after processing the ssl record
	// in the common ssl reassembler.
	}

void SSLv3_Record::Describe(ODesc* d) const
	{
	d->Add("sslrecord");
	}

SSLv3_Endpoint const* SSLv3_Record::GetEndpoint() const
	{
	return endp;
	}

const u_char* SSLv3_Record::GetData() const
	{
	return data;
	}

int SSLv3_Record::ExtractInt24(const u_char* data, int len, int offset)
	{
	if ( offset + int(sizeof(unsigned long)) - 1 > len)
		return 0;

	uint32 val;

	val = 0;
	val = uint32(*(data + offset + 2));
	val |= uint32(*(data + offset + 1)) << 8;
	val |= uint32(*(data + offset)) << 16;

	return val;
	}

int SSLv3_Record::GetRecordLength() const
	{
	return recordLength;
	}

SSLv3_HandshakeRecord::SSLv3_HandshakeRecord(const u_char* data, int len,
				uint16 version, SSLv3_Endpoint const* e)
: SSLv3_Record(data, len, version, e)
	{
	// Weird-check for minimum handshake length header.
	if ( len < 4 )
		{
		e->Interpreter()->Weird("SSLv3x: Handshake-header-length too small!");
		type = 255;
		length = 0;
		next = 0;
		return;
		}

	// Don't analyze encrypted client handshake messages.
	if ( e->IsOrig() &&
	     ((SSLv3_Interpreter*) e->Interpreter())->change_cipher_client_seen &&
	     ! ((SSLv3_Interpreter*) e->Interpreter())->fin_client_seen )
		{
		type = 255;
		length = 0;
		next = 0;
		return;
		}

	// Don't analyze encrypted server handshake messages.
	if ( ! e->IsOrig() &&
	     ((SSLv3_Interpreter*) e->Interpreter())->change_cipher_server_seen &&
	     ! ((SSLv3_Interpreter*) e->Interpreter())->fin_server_seen )
		{
		type = 255;
		length = 0;
		next = 0;
		return;
		}

	type = uint8(*(this->data));
	length = ExtractInt24(data, len, 1);
	if ( length + 4 < len )
		next = new SSLv3_HandshakeRecord(data + length + 4,
					len - (length + 4), version, e);
	else if ( length + 4 > len )
		{
		e->Interpreter()->Weird("SSLv3x: Handshake-header-length inconsistent (too big)");
		next = 0;
		}
	else
		next = 0;
	}

SSLv3_HandshakeRecord::~SSLv3_HandshakeRecord()
	{
	if ( next )
		{
		delete next;
		}
	}

void SSLv3_HandshakeRecord::Deliver(SSLv3_Interpreter* conn)
	{
	SSLv3_HandshakeRecord* it = this;
	while ( it != 0)
		{
		conn->DeliverSSLv3_Record(it);
		it = it->GetNext();
		}
	}

int SSLv3_HandshakeRecord::GetType() const
	{
	return type;
	}

int SSLv3_HandshakeRecord::GetLength() const
	{
	return length;
	}

SSLv3_HandshakeRecord* SSLv3_HandshakeRecord::GetNext()
	{
	return next;
	}

int SSLv3_HandshakeRecord::checkClientHello()
	{
	if ( recordLength < 42 )
		{
		endp->Interpreter()->Weird("SSLv3x: Client hello too small!");
		return 0;
		}

	uint16 version = uint16(data[4] << 8 ) | data[5];
	if ( version != SSLProxy_Analyzer::SSLv30 &&
	     version != SSLProxy_Analyzer::SSLv31 )
		endp->Interpreter()->Weird("SSLv3x: Corrupt version information in Client hello!");

	uint8 sessionIDLength = uint8(data[38]);
	if ( sessionIDLength > 32 )
		{
		endp->Interpreter()->Weird("SSLv3x: SessionID too long in Client hello!");
		return 0;
		}

	uint16 cipherSuiteLength =
		uint16(data[39 + sessionIDLength] << 8 ) |
		data[40 + sessionIDLength];

	if ( cipherSuiteLength < 2 )
		endp->Interpreter()->Weird("SSLv3x: CipherSuite length too small!");

	if ( cipherSuiteLength + sessionIDLength + 41 > recordLength )
		{
		endp->Interpreter()->Weird("SSLv3x: Client hello too small, corrupt length fields!");
		return 0;
		}

	uint8 compressionMethodLength =
		uint8(data[41 + sessionIDLength + cipherSuiteLength]);

	if ( compressionMethodLength < 1 )
		endp->Interpreter()->Weird("SSLv3x: CompressionMethod length too small!");

	if ( sessionIDLength + cipherSuiteLength +
	     compressionMethodLength + 38 != length )
		{
		endp->Interpreter()->Weird("SSLv3x: Corrupt length fields in Client hello!");
		return 0;
		}

	return 1;
	}

int SSLv3_HandshakeRecord::checkServerHello()
	{
	if ( recordLength < 42 )
		{
		endp->Interpreter()->Weird("SSLv3x: Server hello too small!");
		return 0;
		}

	uint16 version = uint16(data[4] << 8) | data[5];
	if ( version != SSLProxy_Analyzer::SSLv30 &&
	     version != SSLProxy_Analyzer::SSLv31 )
		endp->Interpreter()->Weird("SSLv3x: Corrupt version information in Server hello!");

	uint8 sessionIDLength = uint8(data[38]);
	if ( sessionIDLength > 32 )
		{
		endp->Interpreter()->Weird("SSLv3x: SessionID too long in Server hello!");
		return 0;
		}

	if ( (sessionIDLength + 38) != length )
		{
		endp->Interpreter()->Weird("SSLv3x: Corrupt length fields in Server hello!");
		return 0;
		}

	return 1;
	}

SSLv3_AlertRecord::SSLv3_AlertRecord(const u_char* data, int len,
				uint16 version, SSLv3_Endpoint const* e)
: SSLv3_Record(data, len, version, e)
	{
	if ( len < 2 )
		{
		e->Interpreter()->Weird("SSLv3x: Alert header length too small!");
		level = 255;
		description = 255;
		}

	// No further consistency-check, because alerts may be
	// already encrypted.
	level = uint8(*((this->data) + SSL3_1_ALERT_LEVEL_OFFSET));
	description = uint8(*((this->data) + SSL3_1_ALERT_DESCRIPTION_OFFSET));
	}

SSLv3_AlertRecord::~SSLv3_AlertRecord()
	{
	}

int SSLv3_AlertRecord::GetDescription() const
	{
	return description;
	}

int SSLv3_AlertRecord::GetLevel() const
	{
	return level;
	}

void SSLv3_AlertRecord::Deliver(SSLv3_Interpreter* conn)
	{
	conn->DeliverSSLv3_Record(this);
	}

SSLv3_ChangeCipherRecord::SSLv3_ChangeCipherRecord(const u_char* data, int len,
				uint16 version, SSLv3_Endpoint const* e)
: SSLv3_Record(data, len, version, e)
	{
	if ( len < 1 )
		{
		e->Interpreter()->Weird("SSLv3x: Change cipher header length too small!");
		type = 255;
		}
	else
		type = uint8(*((this->data) + SSL3_1_CHANGE_CIPHER_TYPE_OFFSET));
	}

SSLv3_ChangeCipherRecord::~SSLv3_ChangeCipherRecord()
	{
	}

int SSLv3_ChangeCipherRecord::GetType() const
	{
	return type;
	}

void SSLv3_ChangeCipherRecord::Deliver(SSLv3_Interpreter* conn)
	{
	conn->DeliverSSLv3_Record(this);
	}

SSLv3_ApplicationRecord::SSLv3_ApplicationRecord(const u_char* data, int len, uint16 version, SSLv3_Endpoint const* e)
: SSLv3_Record(data, len, version, e)
	{
	}

SSLv3_ApplicationRecord::~SSLv3_ApplicationRecord()
	{
	}

void SSLv3_ApplicationRecord::Deliver(SSLv3_Interpreter* conn)
	{
	conn->DeliverSSLv3_Record(this);
	}
