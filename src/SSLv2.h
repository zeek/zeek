// $Id: SSLv2.h 3526 2006-09-12 07:32:21Z vern $

#ifndef SSLV2_H
#define SSLV2_H

#include "SSLInterpreter.h"
#include "SSLCiphers.h"

// --- constants for SSLv2 ---------------------------------------------------

/*!
 * In SSLv2, each record is of a special message type. Note that the message
 * type is encrypted if the record has been encrypted, so we can determine
 * the message type only if we have a cleartext record.
 */
enum SSLv2_MessageTypes {
	SSLv2_MT_ERROR = 0,	///< can be in cleartext or encrypted
	SSLv2_MT_CLIENT_HELLO = 1,	///< always in cleartext
	SSLv2_MT_CLIENT_MASTER_KEY = 2,	///< always in cleartext
	SSLv2_MT_CLIENT_FINISHED = 3,	///< always encrypted
	SSLv2_MT_SERVER_HELLO = 4,	///< always in cleartext
	SSLv2_MT_SERVER_VERIFY = 5,	///< always encrypted
	SSLv2_MT_SERVER_FINISHED = 6,	///< always encrypted
	SSLv2_MT_REQUEST_CERTIFICATE = 7,	///< always encrypted
	SSLv2_MT_CLIENT_CERTIFICATE = 8,	///< always encrypted
};

// Certificate Type Codes.
//
// Authentication Type Codes
// #define SSL_AT_MD5_WITH_RSA_ENCRYPTION		0x01
// Upper/Lower Bounds
// #define SSL_MAX_MASTER_KEY_LENGTH_IN_BITS	256
// #define SSL_MAX_SESSION_ID_LENGTH_IN_BYTES	16
// #define SSL_MIN_RSA_MODULUS_LENGTH_IN_BYTES	64
// #define SSL_MAX_RECORD_LENGTH_2_BYTE_HEADER	32767
// #define SSL_MAX_RECORD_LENGTH_3_BYTE_HEADER	16383

const uint8 SSLv2_CT_X509_CERTIFICATE = 0x01;

/*!
 * Error codes used in the error record.
 */
enum SSLv2_ErrorCodes {
	SSLv2_PE_NO_CIPHER                    = 0x0001,
	SSLv2_PE_NO_CERTIFICATE               = 0x0002,
	SSLv2_PE_BAD_CERTIFICATE              = 0x0004,
	SSLv2_PE_UNSUPPORTED_CERTIFICATE_TYPE = 0x0006
};

// --- structs ----------------------------------------------------------------

const int SSLv2_CLIENT_HELLO_HEADER_SIZE = 9;
struct SSLv2_ClientHelloHeader {
	uint8  messageType;
	uint16 clientVersion;
	uint16 cipherSpecLength;
	uint16 sessionIdLength;
	uint16 challengeLength;
};

const int SSLv2_SERVER_HELLO_HEADER_SIZE = 11;
struct SSLv2_ServerHelloHeader {
	uint8  messageType;
	uint8  sessionIdHit;
	uint8  certificateType;
	uint16 serverVersion;
	uint16 certificateLength;
	uint16 cipherSpecLength;
	uint16 connectionIdLength;
};

const int SSLv2_CLIENT_MASTER_KEY_HEADER_SIZE = 10;
struct SSLv2_ClientMasterKeyHeader {
	uint8  messageType;
	uint32 cipherKind; // caution: is an uint24
	uint16 clearKeyLength;
	uint16 encryptedKeyLength;
	uint16 keyArgLength;
};

const unsigned int SSLv2_ERROR_RECORD_SIZE = 3;
struct SSLv2_ErrorRecord {
	uint8  messageType;
	uint16 errorCode;
};

const unsigned int SSLv2_CLIENT_FINISHED_HEADER_SIZE = 1;
struct SSLv2_ClientFinished {
	uint8 messageType;
	//char CONNECTION-ID[N-1]
};

struct SSLv2_ServerVerify {
	uint8 messageType;
	//char CHALLENGE-DATA[N-1]
};

struct SSLv2_ServerFinished {
	uint8 messageType;
	//char SESSION-ID-DATA[N-1]
};

// MISSING:
// CLIENT-CERTIFICATE
// REQUEST-CERTIFICATE

/*!
 * States used by the internal SSLv2 automaton.
 */
enum SSLv2_States {
	START,                 ///< start state, no data seen yet
	CLIENT_HELLO_SEEN,     ///< client hello flew by
	NEW_SESSION,           ///< server hello with sessionIdHit == 0 seen
	CACHED_SESSION,        ///< server hello with sessionIdHit != 0 seen
	CLIENT_MASTERKEY_SEEN, ///< we saw a client master key record
	ERROR_SEEN,            ///< we saw an error record
	ERROR_REQUIRED         ///< one of our critical checks failed, so we think we should see an error record
};


// --- forward declarations ---------------------------------------------------

class SSLv2_Interpreter;
class SSLv2_Endpoint;
class SSLv2_Record;
class SSL_DataBlock;
class SSL_RecordBuilder;

// --- class SSLv2_Interpreter ------------------------------------------------

/*!
 * \brief This class is used to analyze SSLv2 connections.
 *
 * Since there's currently no support for decrypting ssl connections, analysis
 * stops when a connection switches to encrypted communication.
 * The interpreter does several checks, both record- and connection-orientated.
 *
 * The record checks mainly consist of consistency checks, where the correct
 * use of the SSL 2.0 specification is checked. Furthermore, the CIPHER-SPECS
 * of the client and the server can be compared to detect non-intersecting sets.
 *
 * The connection check monitors the handshaking process for invalid transitions,
 * until the end of the cleartext phase.
 *
 * Several events are thrown for BroScript, including client connection attempt,
 * server reply, ssl connection establishment/reuse of former connection, proposed
 * cipher suites and certificates seen.
 *
 * \see SSLv2_Endpoint
 */
class SSLv2_Interpreter : public SSL_Interpreter {
public:
	SSLv2_Interpreter(SSLProxy_Analyzer* proxy);
	~SSLv2_Interpreter();

	void NewSSLRecord(SSL_InterpreterEndpoint* s, int length, const u_char* data);
	void analyzeRecord(SSL_InterpreterEndpoint* s, int length, const u_char* data);
	SSLv2_States ClientHelloRecord(SSL_InterpreterEndpoint* s,
	                                int recordLength,
	                                const u_char* recordData);
	SSLv2_States ServerHelloRecord(SSL_InterpreterEndpoint* s,
	                                int recordLength, const u_char* recordData);
	SSLv2_States ClientMasterKeyRecord(SSL_InterpreterEndpoint* s,
	                                    int recordLength,
	                                    const u_char* recordData);
	SSLv2_States ErrorRecord(SSL_InterpreterEndpoint* s,
	                          int recordLength,
	                          const u_char* recordData);

	TableVal* analyzeCiphers(SSL_InterpreterEndpoint* s,
					int length, const u_char* data);
	SSLv2_States ConnState();

	static void printStats();

#define MAX_CIPHERSPEC_SIZE ssl_max_cipherspec_size

	// Global connection counters.
	static uint totalConnections;	///< counter for total sslv2 connections
	static uint analyzedConnections;	///< counter for analyzed (=not partial) connections
	static uint openedConnections;	///< counter for SSLv2 connections with complete handshake
	static uint failedConnections;	///< counter for SSLv2 connections with failed but correct handshake
	static uint weirdConnections;	///< counter for SSLv2 connections with failed and weird handshake

	// Global record counters.
	static uint totalRecords;	///< counter for total SSLv2 records seen
	static uint clientHelloRecords;	///< counter for SSLv2 CLIENT-HELLOs seen
	static uint serverHelloRecords;	///< counter for SSLv2 SERVER-HELLOs seen
	static uint clientMasterKeyRecords;	///< counter for SSLv2 CLIENT-MASTER-KEYSs seen
	static uint errorRecords;	///< counter for SSLv2 ERRORs seen

	// Counters for this instance.
	uint32 records;	///< counter for SSLv2 records of this connection
	SSLv2_States connState;	///< state of connection

	bool bAnalyzedCounted;	///< flag for counting analyzedConnections

	// FIXME: this should be states.
	bool bClientWantsCachedSession;	///< true if the client wants a cached session, false otherwise


protected:
	void BuildInterpreterEndpoints();

	SSL_DataBlock* pClientCipherSpecs;	///< the CIPHER-SPECs from the client
	SSL_DataBlock* pServerCipherSpecs;	///< the CIPHER-SPECs from the server
	SSLv2_CipherSpec usedCipherSpec;	///< the used CIPHER-SPEC for this connection

	// Currently experimental:
	SSL_DataBlock* pConnectionId;	// 16 <= ConnectionId <= 32
	SSL_DataBlock* pChallenge;	// 16 <= Challenge <= 32
	SSL_DataBlock* pSessionId;	// has to be 16 Bytes
	SSL_DataBlock* pMasterClearKey;
	SSL_DataBlock* pMasterEncryptedKey;
	SSL_DataBlock* pClientReadKey;
	SSL_DataBlock* pServerReadKey;
};

// --- class SSLv2_Endpoint ---------------------------------------------------

/*!
 * \brief This class represents an endpoint of an SSLv2 connection.
 *
 * Fully reassembled SSLv2 records are passed to its Deliver() function.
 * There, some counters are updated and the record is then passed to
 * SSLv2_Interpreter::NewSSLRecord().
 */
class SSLv2_Endpoint: public SSL_InterpreterEndpoint {
public:
	SSLv2_Endpoint(SSLv2_Interpreter* interpreter, int is_orig);
	virtual ~SSLv2_Endpoint();

	void Deliver(int len, const u_char* data);

	uint32 sentRecords; ///< counter for sent records of this endpoint
};

#endif
