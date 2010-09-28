// $Id: SSLv2.cc 5988 2008-07-19 07:02:12Z vern $

#include "SSLv2.h"
#include "SSLv3.h"

// --- Initalization of static variables --------------------------------------

uint SSLv2_Interpreter::totalConnections = 0;
uint SSLv2_Interpreter::analyzedConnections = 0;
uint SSLv2_Interpreter::openedConnections = 0;
uint SSLv2_Interpreter::failedConnections = 0;
uint SSLv2_Interpreter::weirdConnections = 0;
uint SSLv2_Interpreter::totalRecords = 0;
uint SSLv2_Interpreter::clientHelloRecords = 0;
uint SSLv2_Interpreter::serverHelloRecords = 0;
uint SSLv2_Interpreter::clientMasterKeyRecords = 0;
uint SSLv2_Interpreter::errorRecords = 0;


// --- SSLv2_Interpreter -------------------------------------------------------

/*!
 * The Constructor.
 *
 * \param proxy Pointer to the SSLProxy_Analyzer who created this instance.
 */
SSLv2_Interpreter::SSLv2_Interpreter(SSLProxy_Analyzer* proxy)
: SSL_Interpreter(proxy)
	{
	++totalConnections;
	records = 0;
	bAnalyzedCounted = false;
	connState = START;

	pServerCipherSpecs = 0;
	pClientCipherSpecs = 0;
	bClientWantsCachedSession = false;
	usedCipherSpec = (SSLv2_CipherSpec) 0;

	pConnectionId = 0;
	pChallenge = 0;
	pSessionId = 0;
	pMasterClearKey = 0;
	pMasterEncryptedKey = 0;
	pClientReadKey = 0;
	pServerReadKey = 0;
	}

/*!
 * The Destructor.
 */
SSLv2_Interpreter::~SSLv2_Interpreter()
	{
	if ( connState != CLIENT_MASTERKEY_SEEN &&
	     connState != CACHED_SESSION &&
	     connState != START &&	// we only complain if we saw some data
	     connState != ERROR_SEEN )
		++failedConnections;

	if ( connState != CLIENT_MASTERKEY_SEEN && connState != CACHED_SESSION )
		++weirdConnections;

	delete pServerCipherSpecs;
	delete pClientCipherSpecs;
	delete pConnectionId;
	delete pChallenge;
	delete pSessionId;
	delete pMasterClearKey;
	delete pMasterEncryptedKey;
	delete pClientReadKey;
	delete pServerReadKey;
	}

/*!
 * This method implements SSL_Interpreter::BuildInterpreterEndpoints()
 */
void SSLv2_Interpreter::BuildInterpreterEndpoints()
	{
	orig = new SSLv2_Endpoint(this, 1);
	resp = new SSLv2_Endpoint(this, 0);
	}

/*!
 * This method prints some counters.
 */
void SSLv2_Interpreter::printStats()
	{
	printf("SSLv2:\n");
	printf("totalConnections    = %u\n", totalConnections);
	printf("analyzedConnections = %u\n", analyzedConnections);
	printf("openedConnections   = %u\n", openedConnections);
	printf("failedConnections   = %u\n", failedConnections);
	printf("weirdConnections   = %u\n", weirdConnections);

	printf("totalRecords            = %u\n", totalRecords);
	printf("clientHelloRecords      = %u\n", clientHelloRecords);
	printf("serverHelloRecords      = %u\n", serverHelloRecords);
	printf("clientMasterKeyRecords  = %u\n", clientMasterKeyRecords);
	printf("errorRecords            = %u\n", errorRecords);

	printf("SSL_RecordBuilder::maxAllocCount     = %u\n", SSL_RecordBuilder::maxAllocCount);
	printf("SSL_RecordBuilder::maxFragmentCount  = %u\n", SSL_RecordBuilder::maxFragmentCount);
	printf("SSL_RecordBuilder::fragmentedHeaders = %u\n", SSL_RecordBuilder::fragmentedHeaders);
	}

/*!
 * \return the current state of the ssl connection
 */
SSLv2_States SSLv2_Interpreter::ConnState()
	{
	return connState;
	}

/*!
 * This method is called by SSLv2_Endpoint::Deliver(). It is the main entry
 * point of this class. The header of the given SSLV2 record is analyzed and
 * its contents are then passed to the corresponding analyzer method. After
 * the record has been analyzed, the ssl connection state is updated.
 *
 * \param s Pointer to the endpoint which sent the record
 * \param length length of SSLv2 record
 * \param data pointer to SSLv2 record to analyze
 */
void SSLv2_Interpreter::NewSSLRecord(SSL_InterpreterEndpoint* s,
					int length, const u_char* data)
	{
	++records;
	++totalRecords;

	if ( ! bAnalyzedCounted )
		{
		++analyzedConnections;
		bAnalyzedCounted = true;
		}

	// We should see a maximum of 4 cleartext records.
	if ( records == 5 )
		{ // so this should never happen
		Weird("SSLv2: Saw more than 4 records, skipping connection...");
		proxy->SetSkip(1);
		return;
		}

	// SSLv2 record header analysis
	uint32 recordLength = 0; // data length of SSLv2 record
	bool isEscape = false;
	uint8 padding = 0;
	const u_char* contents;

	if ( (data[0] & 0x80) > 0 )
		{ // we have a two-byte record header
		recordLength = ((data[0] & 0x7f) << 8) | data[1];
		contents = data + 2;
		if (  recordLength + 2 != uint32(length)  )
			{
			// This should never happen, otherwise
			// we have a bug in the SSL_RecordBuilder.
			Weird("SSLv2: FATAL: recordLength doesn't match data block length!");
			connState = ERROR_REQUIRED;
			proxy->SetSkip(1);
			return;
			}
		}
	else
		{ // We have a three-byte record header.
		recordLength = ((data[0] & 0x3f) << 8) | data[1];
		isEscape = (data[0] & 0x40) != 0;
		padding = data[2];
		contents = data + 3;
		if ( recordLength + 3 != uint32(length) )
			{
			// This should never happen, otherwise
			// we have a bug in the SSL_RecordBuilder.
			Weird("SSLv2: FATAL: recordLength doesn't match data block length!");
			connState = ERROR_REQUIRED;
			proxy->SetSkip(1);
			return;
			}

		if ( padding == 0 && ! isEscape )
			Weird("SSLv2: 3 Byte record header, but no escape, no padding!");
		}

	if ( recordLength == 0 )
		{
		Weird("SSLv2: Record length is zero (no record data)!");
		return;
		}

	if ( isEscape )
		Weird("SSLv2: Record has escape bit set (security escape)!");

	if  ( padding > 0 && connState != CACHED_SESSION &&
	      connState != CLIENT_MASTERKEY_SEEN )
		Weird("SSLv2 record with padding > 0 in cleartext!");

	// MISSING:
	// A final consistency check is done when a block cipher is used
	// and the protocol is using encryption. The amount of data present
	// in a record (RECORD-LENGTH))must be a multiple of the cipher's
	// block size.  If the received record is not a multiple of the
	// cipher's block size then the record is considered damaged, and it
	// is to be treated as if an "I/O Error" had occurred (i.e. an
	// unrecoverable error is asserted and the connection is closed).

	switch ( connState ) {
	case START:
		// Only CLIENT-HELLLOs allowed here.
		if ( contents[0] != SSLv2_MT_CLIENT_HELLO )
			{
			Weird("SSLv2: First packet is not a CLIENT-HELLO!");
			analyzeRecord(s, recordLength, contents);
			connState = ERROR_REQUIRED;
			}
		else
			connState = ClientHelloRecord(s, recordLength, contents);
		break;

	case CLIENT_HELLO_SEEN:
		// Only SERVER-HELLOs or ERRORs allowed here.
		if ( contents[0] == SSLv2_MT_SERVER_HELLO )
			connState = ServerHelloRecord(s, recordLength, contents);
		else if ( contents[0] == SSLv2_MT_ERROR )
			connState = ErrorRecord(s, recordLength, contents);
		else
			{
			Weird("SSLv2: State violation in CLIENT_HELLO_SEEN!");
			analyzeRecord(s, recordLength, contents);
			connState = ERROR_REQUIRED;
			}
		break;

	case NEW_SESSION:
		// We expect a client master key.
		if ( contents[0] == SSLv2_MT_CLIENT_MASTER_KEY )
			connState = ClientMasterKeyRecord(s, recordLength, contents);
		else if ( contents[0] == SSLv2_MT_ERROR )
			connState = ErrorRecord(s, recordLength, contents);
		else
			{
			Weird("SSLv2: State violation in NEW_SESSION or encrypted record!");
			analyzeRecord(s, recordLength, contents);
			connState = ERROR_REQUIRED;
			}

		delete pServerCipherSpecs;
		pServerCipherSpecs = 0;
		break;

	case CACHED_SESSION:
		delete pServerCipherSpecs;
		pServerCipherSpecs = 0;
		// No break here.

	case CLIENT_MASTERKEY_SEEN:
		// If no error record, no further analysis.
		if ( contents[0] == SSLv2_MT_ERROR &&
		     recordLength == SSLv2_ERROR_RECORD_SIZE )
			connState = ErrorRecord(s, recordLength, contents);
		else
			{
			// So we finished the cleartext handshake.
			// Skip all further data.

			proxy->SetSkip(1);
			++openedConnections;
			}
		break;

	case ERROR_REQUIRED:
		if ( contents[0] == SSLv2_MT_ERROR )
			connState = ErrorRecord(s, recordLength, contents);
		else
			{
			// We lost tracking: this should not happen.
			Weird("SSLv2: State inconsistency in ERROR_REQUIRED (lost tracking!)!");
			analyzeRecord(s, recordLength, contents);
			connState = ERROR_REQUIRED;
			}
		break;

	case ERROR_SEEN:
		// We don't have recoverable errors in cleartext phase,
		// so we shouldn't see anymore packets.
		Weird("SSLv2: Traffic after error record!");
		analyzeRecord(s, recordLength, contents);
		break;

	default:
		internal_error("SSLv2: unknown state");
		break;
	}
	}

/*!
 * This method is called whenever the connection tracking failed. It calls
 * the corresponding analyzer method for the given SSLv2 record, but does not
 * update the ssl connection state.
 *
 * \param s Pointer to the endpoint which sent the record
 * \param length length of SSLv2 record
 * \param data pointer to SSLv2 record to analyze
 */
void SSLv2_Interpreter::analyzeRecord(SSL_InterpreterEndpoint* s,
					int length, const u_char* data)
	{
	switch ( data[0] ) {
	case SSLv2_MT_ERROR:
		ErrorRecord(s, length, data);
		break;

	case SSLv2_MT_CLIENT_HELLO:
		ClientHelloRecord(s, length, data);
		break;

	case SSLv2_MT_CLIENT_MASTER_KEY:
		ClientMasterKeyRecord(s, length, data);
		break;

	case SSLv2_MT_SERVER_HELLO:
		ServerHelloRecord(s, length, data);
		break;

	case SSLv2_MT_CLIENT_FINISHED:
	case SSLv2_MT_SERVER_VERIFY:
	case SSLv2_MT_SERVER_FINISHED:
	case SSLv2_MT_REQUEST_CERTIFICATE:
	case SSLv2_MT_CLIENT_CERTIFICATE:
		Weird("SSLv2: Encrypted record type seems to be in cleartext");
		break;

	default:
		// Unknown record type.
		Weird("SSLv2: Unknown record type or encrypted record");
		break;
	}
	}

/*!
 * This method analyses a SSLv2 CLIENT-HELLO record.
 *
 * \param s Pointer to the endpoint which sent the record
 * \param length length of SSLv2 CLIENT-HELLO record
 * \param data pointer to SSLv2 CLIENT-HELLO record to analyze
 *
 * \return the updated state of the current ssl connection
 */
SSLv2_States SSLv2_Interpreter::ClientHelloRecord(SSL_InterpreterEndpoint* s,
					int recordLength, const u_char* recordData)
	{
	// This method gets the record's data (without the header).
	++clientHelloRecords;

	if ( s != orig )
		Weird("SSLv2: CLIENT-HELLO record from server!");

	// There should not be any pending data in the SSLv2 reassembler,
	// because the client should wait for a server response.
	if ( ((SSLv2_Endpoint*) s)->isDataPending() )
		Weird("SSLv2: Pending data in SSL_RecordBuilder after CLIENT-HELLO!");

	// Client hello minimum header size check.
	if ( recordLength < SSLv2_CLIENT_HELLO_HEADER_SIZE )
		{
		Weird("SSLv2: CLIENT-HELLO is too small!");
		return ERROR_REQUIRED;
		}

	// Extract the data of the client hello header.
	SSLv2_ClientHelloHeader ch;
	ch.clientVersion = uint16(recordData[1] << 8) | recordData[2];
	ch.cipherSpecLength = uint16(recordData[3] << 8) | recordData[4];
	ch.sessionIdLength = uint16(recordData[5] << 8) | recordData[6];
	ch.challengeLength = uint16(recordData[7] << 8) | recordData[8];

	if ( ch.clientVersion != SSLProxy_Analyzer::SSLv20 &&
	     ch.clientVersion != SSLProxy_Analyzer::SSLv30 &&
	     ch.clientVersion != SSLProxy_Analyzer::SSLv31 )
		{
		Weird("SSLv2: Unsupported SSL-Version in CLIENT-HELLO");
		return ERROR_REQUIRED;
		}

	if ( ch.challengeLength + ch.cipherSpecLength + ch.sessionIdLength +
	     SSLv2_CLIENT_HELLO_HEADER_SIZE != recordLength )
		{
		Weird("SSLv2: Size inconsistency in CLIENT-HELLO");
		return ERROR_REQUIRED;
		}

	// The CIPHER-SPECS-LENGTH must be > 0 and a multiple of 3.
	if ( ch.cipherSpecLength == 0 || ch.cipherSpecLength % 3 != 0 )
		{
		Weird("SSLv2: Nonconform CIPHER-SPECS-LENGTH in CLIENT-HELLO.");
		return ERROR_REQUIRED;
		}

	// The SESSION-ID-LENGTH must either be zero or 16.
	if ( ch.sessionIdLength != 0 && ch.sessionIdLength != 16 )
		Weird("SSLv2: Nonconform SESSION-ID-LENGTH in CLIENT-HELLO.");

	if ( (ch.challengeLength < 16) || (ch.challengeLength > 32))
		Weird("SSLv2: Nonconform CHALLENGE-LENGTH in CLIENT-HELLO.");

	const u_char* ptr = recordData;
	ptr += SSLv2_CLIENT_HELLO_HEADER_SIZE + ch.cipherSpecLength;

	pSessionId = new SSL_DataBlock(ptr, ch.sessionIdLength);

	// If decrypting, store the challenge.
	if ( ssl_store_key_material && ch.challengeLength <= 32 )
		pChallenge = new SSL_DataBlock(ptr, ch.challengeLength);

	bClientWantsCachedSession = ch.sessionIdLength != 0;

	TableVal* currentCipherSuites =
		analyzeCiphers(s, ch.cipherSpecLength,
			recordData + SSLv2_CLIENT_HELLO_HEADER_SIZE);

	fire_ssl_conn_attempt(ch.clientVersion, currentCipherSuites);

	return CLIENT_HELLO_SEEN;
	}

/*!
 * This method analyses a SSLv2 SERVER-HELLO record.
 *
 * \param s Pointer to the endpoint which sent the record
 * \param length length of SSLv2 SERVER-HELLO record
 * \param data pointer to SSLv2 SERVER-HELLO record to analyze
 *
 * \return the updated state of the current ssl connection
 */
SSLv2_States SSLv2_Interpreter::ServerHelloRecord(SSL_InterpreterEndpoint* s,
					int recordLength, const u_char* recordData)
	{
	++serverHelloRecords;
	TableVal* currentCipherSuites = NULL;

	if ( s != resp )
		Weird("SSLv2: SERVER-HELLO from client!");

	if ( recordLength < SSLv2_SERVER_HELLO_HEADER_SIZE )
		{
		Weird("SSLv2: SERVER-HELLO is too small!");
		return ERROR_REQUIRED;
		}

	// Extract the data of the client hello header.
	SSLv2_ServerHelloHeader sh;
	sh.sessionIdHit = recordData[1];
	sh.certificateType = recordData[2];
	sh.serverVersion = uint16(recordData[3] << 8) | recordData[4];
	sh.certificateLength = uint16(recordData[5] << 8) | recordData[6];
	sh.cipherSpecLength = uint16(recordData[7] << 8) | recordData[8];
	sh.connectionIdLength = uint16(recordData[9] << 8) | recordData[10];

	if ( sh.serverVersion != SSLProxy_Analyzer::SSLv20 )
		{
		Weird("SSLv2: Unsupported SSL-Version in SERVER-HELLO");
		return ERROR_REQUIRED;
		}

	if ( sh.certificateLength + sh.cipherSpecLength +
	     sh.connectionIdLength +
	     SSLv2_SERVER_HELLO_HEADER_SIZE != recordLength )
		{
		Weird("SSLv2: Size inconsistency in SERVER-HELLO");
		return ERROR_REQUIRED;
		}

	// The length of the CONNECTION-ID must be between 16 and 32 bytes.
	if ( sh.connectionIdLength < 16 || sh.connectionIdLength > 32 )
		Weird("SSLv2: Nonconform CONNECTION-ID-LENGTH in SERVER-HELLO");

	// If decrypting, store the connection ID.
	if ( ssl_store_key_material && sh.connectionIdLength <= 32 )
		{
		const u_char* ptr = recordData;

		ptr += SSLv2_SERVER_HELLO_HEADER_SIZE + sh.cipherSpecLength +
		       sh.certificateLength;

		pConnectionId = new SSL_DataBlock(ptr, sh.connectionIdLength);
		}

	if  ( sh.sessionIdHit == 0  )
		{
		// Generating reusing-connection event.
		EventHandlerPtr event = ssl_session_insertion;

		if ( event )
			{
			TableVal* sessionIDTable =
				MakeSessionID(
					recordData +
						SSLv2_SERVER_HELLO_HEADER_SIZE +
						sh.certificateLength +
						sh.cipherSpecLength,
					sh.connectionIdLength);

			val_list* vl = new val_list;
			vl->append(proxy->BuildConnVal());
			vl->append(sessionIDTable);

			proxy->ConnectionEvent(ssl_session_insertion, vl);
			}
		}

	SSLv2_States nextState;

	if ( sh.sessionIdHit != 0 )
		{ // we're using a cached session

		// There should not be any pending data in the SSLv2
		// reassembler, because the server should wait for a
		// client response.
		if ( ((SSLv2_Endpoint*) s)->isDataPending() )
			{
			// But turns out some SSL Implementations do this
			// when using a cached session.
			}

		// Consistency check for SESSION-ID-HIT.
		if ( ! bClientWantsCachedSession )
			Weird("SSLv2: SESSION-ID hit in SERVER-HELLO, but no SESSION-ID in CLIENT-HELLO!");

		// If the SESSION-ID-HIT flag is non-zero then the
		// CERTIFICATE-TYPE, CERTIFICATE-LENGTH and
		// CIPHER-SPECS-LENGTH fields will be zero.
		if ( sh.certificateType != 0 || sh.certificateLength != 0 ||
		     sh.cipherSpecLength != 0 )
			Weird("SSLv2: SESSION-ID-HIT, but session data in SERVER-HELLO");

		// Generate reusing-connection event.
		if ( pSessionId )
			{
			fire_ssl_conn_reused(pSessionId);
			delete pSessionId;
			pSessionId = 0;
			}

		nextState = CACHED_SESSION;
		}
	else
		{ // we're starting a new session

		// There should not be any pending data in the SSLv2
		// reassembler, because the server should wait for
		// a client response.
		if ( ((SSLv2_Endpoint*) s)->isDataPending() )
			Weird("SSLv2: Pending data in SSL_RecordBuilder after SERVER-HELLO (new session)!");

		// TODO: check certificate length ???
		if ( sh.certificateLength == 0 )
			Weird("SSLv2: No certificate in SERVER-HELLO!");

		// The CIPHER-SPECS-LENGTH must be > zero and a multiple of 3.
		if ( sh.cipherSpecLength == 0 )
			Weird("SSLv2: No CIPHER-SPECS in SERVER-HELLO!");

		if ( sh.cipherSpecLength % 3 != 0 )
			{
			Weird("SSLv2: Nonconform CIPHER-SPECS-LENGTH in SERVER-HELLO");
			return ERROR_REQUIRED;
			}

		const u_char* ptr = recordData;
		ptr += sh.certificateLength + SSLv2_SERVER_HELLO_HEADER_SIZE;
		currentCipherSuites = analyzeCiphers(s, sh.cipherSpecLength, ptr);

		nextState = NEW_SESSION;
		}

	// Check if at least one cipher is supported by the client.
	if ( pClientCipherSpecs && pServerCipherSpecs )
		{
		bool bFound = false;
		for ( int i = 0; i < pClientCipherSpecs->len; i += 3 )
			{
			for ( int j = 0; j < pServerCipherSpecs->len; j += 3 )
				{
				if ( memcmp(pClientCipherSpecs + i,
					    pServerCipherSpecs + j, 3) == 0 )
					{
					bFound = true;
					i = pClientCipherSpecs->len;
					break;
					}
				}
			}

		if ( ! bFound )
			{
			Weird("SSLv2: Client's and server's CIPHER-SPECS don't match!");
			nextState = ERROR_REQUIRED;
			}

		delete pClientCipherSpecs;
		pClientCipherSpecs = 0;
		}

	// Certificate analysis.
	if ( sh.certificateLength > 0 && ssl_analyze_certificates != 0 )
		{
		analyzeCertificate(s, recordData + SSLv2_SERVER_HELLO_HEADER_SIZE,
			sh.certificateLength, sh.certificateType, false);
		}

	if ( nextState == NEW_SESSION )
		// generate server-reply event
		fire_ssl_conn_server_reply(sh.serverVersion, currentCipherSuites);

	else if ( nextState == CACHED_SESSION )
		{ // generate server-reply event
		fire_ssl_conn_server_reply(sh.serverVersion, currentCipherSuites);
		// Generate a connection-established event with a dummy
		// cipher suite, since we can't remember session information
		// (yet).
		// Note: A new session identifier is sent encrypted in SSLv2!
		fire_ssl_conn_established(sh.serverVersion, 0xABCD);
		}
	else
		// Unref, since the table is not delivered to any event.
	        Unref(currentCipherSuites);

	return nextState;
	}

/*!
 * This method analyses a SSLv2 CLIENT-MASTER-KEY record.
 *
 * \param s Pointer to the endpoint which sent the record
 * \param length length of SSLv2 CLIENT-MASTER-KEY record
 * \param data pointer to SSLv2 CLIENT-MASTER-KEY record to analyze
 *
 * \return the updated state of the current ssl connection
 */
SSLv2_States SSLv2_Interpreter::
	ClientMasterKeyRecord(SSL_InterpreterEndpoint* s, int recordLength,
				const u_char* recordData)
	{
	++clientMasterKeyRecords;
	SSLv2_States nextState = CLIENT_MASTERKEY_SEEN;

	if ( s != orig )
		Weird("SSLv2: CLIENT-MASTER-KEY from server!");

	if ( recordLength < SSLv2_CLIENT_MASTER_KEY_HEADER_SIZE )
		{
		Weird("SSLv2: CLIENT-MASTER-KEY is too small!");
		return ERROR_REQUIRED;
		}

	// Extract the data of the client master key header.
	SSLv2_ClientMasterKeyHeader cmk;
	cmk.cipherKind =
		((recordData[1] << 16) | recordData[2] << 8) | recordData[3];
	cmk.clearKeyLength = uint16(recordData[4] << 8) | recordData[5];
	cmk.encryptedKeyLength = uint16(recordData[6] << 8) | recordData[7];
	cmk.keyArgLength = uint16(recordData[8] << 8) | recordData[9];

	if ( cmk.clearKeyLength + cmk.encryptedKeyLength + cmk.keyArgLength +
	     SSLv2_CLIENT_MASTER_KEY_HEADER_SIZE != recordLength )
		{
		Weird("SSLv2: Size inconsistency in CLIENT-MASTER-KEY");
		return ERROR_REQUIRED;
		}

	// Check if cipher is supported by the server.
	if ( pServerCipherSpecs )
		{
		bool bFound = false;
		for ( int i = 0; i < pServerCipherSpecs->len; i += 3 )
			{
			uint32 cipherSpec =
				((pServerCipherSpecs->data[i] << 16) |
				 pServerCipherSpecs->data[i+1] << 8) |
				pServerCipherSpecs->data[i+2];

			if ( cmk.cipherKind == cipherSpec )
				{
				bFound = true;
				break;
				}
			}

		if ( ! bFound )
			{
			Weird("SSLv2: Client chooses unadvertised cipher in CLIENT-MASTER-KEY!");
			nextState = ERROR_REQUIRED;
			}
		else
			nextState = CLIENT_MASTERKEY_SEEN;

		delete pServerCipherSpecs;
		pServerCipherSpecs = 0;
		}

	// TODO: check if cipher has been advertised before.

	SSL_CipherSpec* pCipherSpecTemp = 0;

	HashKey h(static_cast<bro_uint_t>(cmk.cipherKind));
	pCipherSpecTemp = (SSL_CipherSpec*) SSL_CipherSpecDict.Lookup(&h);
	if ( ! pCipherSpecTemp || ! (pCipherSpecTemp->flags & SSL_FLAG_SSLv20) )
		Weird("SSLv2: Unknown CIPHER-SPEC in CLIENT-MASTER-KEY!");
	else
		{ // check for conistency of clearKeyLength
		if ( cmk.clearKeyLength * 8 != pCipherSpecTemp->clearKeySize )
			{
			Weird("SSLv2: Inconsistency of clearKeyLength in CLIENT-MASTER-KEY!");
			// nextState = ERROR_REQUIRED;
			}

		// TODO: check for consistency of encryptedKeyLength.
		// TODO: check for consistency of keyArgLength.
//		switch ( cmk.cipherKind )
//			{
//			case SSL_CK_RC4_128_WITH_MD5:
//			case SSL_CK_RC4_128_EXPORT40_WITH_MD5:
//				if ( cmk.keyArgLength != 0 )
//					{
//					Weird("SSLv2: Inconsistency of keyArgLength in CLIENT-MASTER-KEY!");
//					//nextState = ERROR_REQUIRED;
//					}
//			break;
//			case SSL_CK_DES_64_CBC_WITH_MD5:
//			case SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5:
//			case SSL_CK_RC2_128_CBC_WITH_MD5:
//				case SSL_CK_IDEA_128_CBC_WITH_MD5:
//			case SSL_CK_DES_192_EDE3_CBC_WITH_MD5:
//				if ( cmk.keyArgLength != 8 )
//					{
//					Weird("SSLv2: Inconsistency of keyArgLength in CLIENT-MASTER-KEY!");
//					}
//			break;
//			}
		}

	// Remember the used cipher spec.
	usedCipherSpec = SSLv2_CipherSpec(cmk.cipherKind);

	// If decrypting, store the clear key part of the master key.
	if ( ssl_store_key_material /* && cmk.clearKeyLength == 11 */ )
		{
		pMasterClearKey =
			new SSL_DataBlock((recordData + SSLv2_CLIENT_MASTER_KEY_HEADER_SIZE), cmk.clearKeyLength);

		pMasterEncryptedKey =
			new SSL_DataBlock((recordData + SSLv2_CLIENT_MASTER_KEY_HEADER_SIZE + cmk.clearKeyLength ), cmk.encryptedKeyLength);
		}

	if ( nextState == CLIENT_MASTERKEY_SEEN )
		fire_ssl_conn_established(SSLProxy_Analyzer::SSLv20,
						cmk.cipherKind);

	return nextState;
	}


/*!
 * This method analyses a SSLv2 ERROR record.
 *
 * \param s Pointer to the endpoint which sent the record
 * \param length length of SSLv2 ERROR record
 * \param data pointer to SSLv2 ERROR record to analyze
 *
 * \return the updated state of the current ssl connection
 */
SSLv2_States SSLv2_Interpreter::ErrorRecord(SSL_InterpreterEndpoint* s,
					int recordLength, const u_char* recordData)
	{
	++errorRecords;

	if ( unsigned(recordLength) != SSLv2_ERROR_RECORD_SIZE )
		{
		Weird("SSLv2: Size mismatch in Error Record!");
		return ERROR_REQUIRED;
		}

	SSLv2_ErrorRecord er;
	er.errorCode = (recordData[1] << 8) | recordData[2];
	SSL3x_AlertLevel al = SSL3x_AlertLevel(255);

	switch ( er.errorCode ) {
	case SSLv2_PE_NO_CIPHER:
		// The client doesn't support a cipher which the server
		// supports.  Only from client to server and not recoverable!
		al = SSL3x_ALERT_LEVEL_FATAL;
		break;

	case SSLv2_PE_NO_CERTIFICATE:
		if ( s == orig )
			// from client to server: not recoverable
			al = SSL3x_ALERT_LEVEL_FATAL;
		else
			// from server to client: recoverable
			al = SSL3x_ALERT_LEVEL_WARNING;
		break;

	case SSLv2_PE_BAD_CERTIFICATE:
		if ( s == orig )
			// from client to server: not recoverable
			al = SSL3x_ALERT_LEVEL_FATAL;
		else
			// from server to client: recoverable
			al = SSL3x_ALERT_LEVEL_WARNING;
		break;

	case SSLv2_PE_UNSUPPORTED_CERTIFICATE_TYPE:
		if ( s == orig )
			// from client to server: not recoverable
			al = SSL3x_ALERT_LEVEL_FATAL;
		else
			// from server to client: recoverable
			al = SSL3x_ALERT_LEVEL_WARNING;
		break;

	default:
		al = SSL3x_ALERT_LEVEL_FATAL;
		break;
	}

	fire_ssl_conn_alert(SSLProxy_Analyzer::SSLv20, al, er.errorCode);

	return ERROR_SEEN;
	}

/*!
 * This method analyses a set of SSLv2 cipher suites.
 *
 * \param s Pointer to the endpoint which sent the cipher suites
 * \param length length of cipher suites
 * \param data pointer to cipher suites to analyze
 *
 * \return a pointer to a Bro TableVal (of type cipher_suites_list) which contains
 *         the cipher suites list of the current analyzed record
 */
TableVal* SSLv2_Interpreter::analyzeCiphers(SSL_InterpreterEndpoint* s,
						int length, const u_char* data)
	{
	if ( length > MAX_CIPHERSPEC_SIZE )
		{
		if ( s == orig )
			Weird("SSLv2: Client has CipherSpecs > MAX_CIPHERSPEC_SIZE");
		else
			Weird("SSLv2: Server has CipherSpecs > MAX_CIPHERSPEC_SIZE");
		}
	else
		{ // cipher specs are not too big
		if ( ssl_compare_cipherspecs )
			{ // store cipher specs for state analysis
			if ( s == resp )
				pServerCipherSpecs =
					new SSL_DataBlock(data, length);
			else
				pClientCipherSpecs =
					new SSL_DataBlock(data, length);
			}
		}

	const u_char* pCipher = data;
	bool bExtractCipherSuite = false;
	TableVal* pCipherTable = 0;

	// We only extract the cipher suite when the corresponding
	// ssl events are defined (otherwise we do work for nothing
	// and suffer a memory leak).
	// FIXME: This check needs to be done only once!
	if ( (s == orig && ssl_conn_attempt) ||
	     (s == resp && ssl_conn_server_reply) )
		{
		pCipherTable = new TableVal(cipher_suites_list);
		bExtractCipherSuite = true;
		}

	for ( int i = 0; i < length; i += 3 )
		{
		SSL_CipherSpec* pCurrentCipherSpec;
		uint32 cipherSpecID =
			((pCipher[0] << 16) | pCipher[1] << 8) | pCipher[2];

		// Check for unknown cipher specs.
		HashKey h(static_cast<bro_uint_t>(cipherSpecID));
		pCurrentCipherSpec =
			(SSL_CipherSpec*) SSL_CipherSpecDict.Lookup(&h);

		if ( ! pCurrentCipherSpec )
			{
			if ( s == orig )
				Weird("SSLv2: Unknown CIPHER-SPEC in CLIENT-HELLO!");
			else
				Weird("SSLv2: Unknown CIPHER-SPEC in SERVER-HELLO!");
			}

		if ( bExtractCipherSuite )
			{
			Val* index = new Val(cipherSpecID, TYPE_COUNT);
			pCipherTable->Assign(index, 0);
			Unref(index);
			}

		pCipher += 3;
		}

	return pCipherTable;
	}

// --- SSLv2_EndPoint ---------------------------------------------------------

/*!
 * The constructor.
 *
 * \param interpreter Pointer to the SSLv2 interpreter to whom this endpoint belongs to
 * \param is_orig true if this is the originating endpoint of the ssl connection,
 *                false otherwise
 */
SSLv2_Endpoint::SSLv2_Endpoint(SSLv2_Interpreter* interpreter, int is_orig)
: SSL_InterpreterEndpoint(interpreter, is_orig)
	{
	sentRecords = 0;
	}

/*!
 * The destructor.
 */
SSLv2_Endpoint::~SSLv2_Endpoint()
	{
	}

/*!
 * This method is called by the SSLProxy_Analyzer with a complete reassembled
 * SSLv2 record. It passes the record to SSLv2_Interpreter::NewSSLRecord().
 *
 * \param t <b>reserved</b> (always zero)
 * \param seq <b>reserved</b> (always zero)
 * \param len length of the data block containing the ssl record
 * \param data pointer to the data block containing the ssl record
 */
void SSLv2_Endpoint::Deliver(int len, const u_char* data)
	{
	++((SSLv2_Endpoint*)peer)->sentRecords;

	((SSLv2_Interpreter*)interpreter)->NewSSLRecord(this, len, data);
	}
