// $Id: SSLv3.h 3526 2006-09-12 07:32:21Z vern $

#ifndef sslv3_h
#define sslv3_h

#include "SSLInterpreter.h"
#include "SSLProxy.h"
#include "SSLv3Automaton.h"
#include "SSLDefines.h"

// Offsets in SSL record layer header.
const int SSL3_1_CONTENTTYPEOFFSET = 0;
const int SSL3_1_VERSIONTYPEOFFSET = 1;
const int SSL3_1_LENGTHOFFSET = 3;
const int SSL3_1_HEADERLENGTH = 5;

// --- forward declarations ---------------------------------------------------

class SSL_Interpreter;
class SSL_InterpreterEndpoint;
class SSLProxy_Analyzer;
class SSLv3_Endpoint;
class SSLv3_Record;
class SSLv3_HandshakeRecord;
class SSLv3_AlertRecord;
class SSLv3_ApplicationRecord;
class SSLv3_ChangeCipherRecord;
class CertStore;
struct SSL_CipherSpec;

// --- enums for SSLv3.0/3.1 message handling ---------------------------------

enum SSL3_1_ContentType {
	SSL3_1_TYPE_CHANGE_CIPHER_SPEC = 20,
	SSL3_1_TYPE_ALERT = 21,
	SSL3_1_TYPE_HANDSHAKE = 22,
	SSL3_1_TYPE_APPLICATION_DATA = 23
};

enum SSL3_1_HandshakeType {
	SSL3_1_HELLO_REQUEST = 0,
	SSL3_1_CLIENT_HELLO = 1,
	SSL3_1_SERVER_HELLO = 2,
	SSL3_1_CERTIFICATE = 11,
	SSL3_1_SERVER_KEY_EXCHANGE = 12,
	SSL3_1_CERTIFICATE_REQUEST = 13,
	SSL3_1_SERVER_HELLO_DONE = 14,
	SSL3_1_CERTIFICATE_VERIFY = 15,
	SSL3_1_CLIENT_KEY_EXCHANGE = 16,
	SSL3_1_FINISHED = 20
};

enum SSL3_1_AlertDescription {
	SSL3_1_CLOSE_NOTIFY = 0,
	SSL3_1_UNEXPECTED_MESSAGE = 10,
	SSL3_1_BAD_RECORD_MAC = 20,
	SSL3_1_DECRYPTION_FAILED = 21,
	SSL3_1_RECORD_OVERFLOW = 22,
	SSL3_1_DECOMPRESSION_FAILURE = 30,
	SSL3_1_HANDSHAKE_FAILURE = 40,
	SSL3_0_NO_CERTIFICATE = 41,
	SSL3_1_BAD_CERTIFICATE = 42,
	SSL3_1_UNSUPPORTED_CERTIFICATE = 43,
	SSL3_1_CERTIFICATE_REVOKED = 44,
	SSL3_1_CERTIFICATE_EXPIRED = 45,
	SSL3_1_CERTIFICATE_UNKNOWN = 46,
	SSL3_1_ILLEGAL_PARAMETER = 47,
	SSL3_1_UNKNOWN_CA = 48,
	SSL3_1_ACCESS_DENIED = 49,
	SSL3_1_DECODE_ERROR = 50,
	SSL3_1_DECRYPT_ERROR = 51,
	SSL3_1_EXPORT_RESTRICTION = 60,
	SSL3_1_PROTOCOL_VERSION = 70,
	SSL3_1_INSUFFICIENT_SECURITY = 71,
	SSL3_1_INTERNAL_ERROR = 80,
	SSL3_1_USER_CANCELED = 90,
	SSL3_1_NO_RENEGOTIATION = 100
};

enum SSL3x_AlertLevel {
	SSL3x_ALERT_LEVEL_WARNING = 1,
	SSL3x_ALERT_LEVEL_FATAL = 2
};

// --- structs ----------------------------------------------------------------

struct SSLv3x_Random {
	uint32 gmt_unix_time;
	SSL_DataBlock* random_bytes;	// 28-bytes
};

struct SSLv3x_ServerRSAParams {
	SSL_DataBlock* rsa_modulus;	// <1..2^16-1>
	SSL_DataBlock* rsa_exponent;	// <1..2^16-1>
};

struct SSLv3x_ServerDHParams{
	SSL_DataBlock* dh_p;	// <1..2^16-1>
	SSL_DataBlock* dh_g;	// <1..2^16-1>
	SSL_DataBlock* dh_Ys;	// <1..2^16-1>
};

struct SSLv3x_EncryptedPremasterSecret{
	SSL_DataBlock* encryptedSecret;
};

struct SSLv3x_ClientDHPublic{
	SSL_DataBlock* dh_Yc;	// <1..2^16-1>
};

// ----------------------------------------------------------------------------

/**
 * Class SSLv3_Interpreter is the implementation for a SSLv3.0/SSLv3.1 connection
 * interpreter (derived from the abstract class SSL_Interpreter).
 *
 * The corresponding SSLProxy_Analyzer creates an instance of this class and
 * properly initialises the corresponding SSLv3_Endpoints by calling the
 * SSL_Interpreter's Init() method which then invokes the BuildInterpreterEndpoints() method
 * (of the SSLv3_Interpreter) which causes the SSLv3_Endpoints to be created properly.
 *
 * The SSLv3_Interpreter receives the four various SSLv3_Records:
 * - SSLv3_HandshakeRecord
 * - SSLv3_AlertRecord
 * - SSLv3_ChangeCipherRecord
 * - SSLv3_ApplicationRecord
 * via the DeliverSSLv3_Record() methods from the two corresponding SSLv3_Endpoints
 * (which get fed by the SSLProxy_Analyzer).
 *
 * There is one global static SSLv3_Automaton which describes the possible transitions
 * in the SSLv3.0/SSLv3.1 state machine for the handshaking phase. This automaton
 * is initialised once, when Bro sees the first SSL connection. By the attribute
 * currentState every instance of SSLv3_Interpreter holds the automaton state it
 * is currently in and so is able
 * to track the correctness of the SSL handshaking process. It weird-checks and verifies
 * all arriving SSL records up to the point where handshaking is finished or an
 * error occures caused by weird SSL records or not allowed transitions in the
 * state machine. Information that was negotiated between the client and server
 * during the handshaking phase is/may also be stored. That is:
 * - used SSL version
 * - negotiated cipher suite
 * - session ID
 * - client/server random
 * - key exchange algorithms
 * - cryptographic parameters
 * - encrypted pre-master secret
 *
 * The certificates are verified using the analyzeCertificate() method of the
 * SSL_Interpreter class.
 * Events for Bro scripting are thrown for client connection attempt, server reply,
 * ssl connection establishment/reuse of former connection, proposed cipher suites and
 * seen certificates.
 *
 * @see SSLv3_Endpoint
 */
class SSLv3_Interpreter : public SSL_Interpreter {
public:
	/** The constructor takes the SSLProxy_Analyzer as argument,
	 * that created this SSLv3_Interpreter.
	 *
	 * @param proxy the creating SSL_ConectionProxy
	 */
	SSLv3_Interpreter(SSLProxy_Analyzer* proxy);
	~SSLv3_Interpreter();

	/** Delivers an SSLv3_HandshakeRecord to the SSLv3_Interpreter.
	 * The record gets verified and it is checked whether it is allowed
	 * in the current phase of the handshaking process.
	 *
	 * @param rec the SSLv3_HandshakeRecord
	 */
	void DeliverSSLv3_Record(SSLv3_HandshakeRecord* rec);

	/** Delivers an SSLv3_AlertRecord to the SSLv3_Interpreter.
	 * The record gets verified and weird checked.
	 *
	 * @param rec the SSLv3_AlertRecord
	 */
	void DeliverSSLv3_Record(SSLv3_AlertRecord* rec);

	/** Delivers an SSLv3_ChangeCipherRecord to the SSLv3_Interpreter.
	 * The record gets verified and weird checked. If a change cipher
	 * record is received the next record from this endpoint needs
	 * to be a finished message.
	 *
	 * @param rec the SSLv3_ChangeCipherRecord
	 */
	void DeliverSSLv3_Record(SSLv3_ChangeCipherRecord* rec);

	/** Delivers a SSLv3_ApplicationRecord to the SSLv3_Interpreter.
	 * It is checked, whether handshaking phase is already finished
	 * and sending application data is valid (the normal case is,
	 * that after finishing the handshaking phase, all further data
	 * is skipped).
	 *
	 * @param rec the SSLv3_AlertRecord
	 */
	void DeliverSSLv3_Record(SSLv3_ApplicationRecord* rec);

	/** This method sets the currentState variable of this SSLv3_Interpreter
	 * and so sets the SSLv3.0/SSLv3.1 state machine to the state passed
	 * as parameter.It is invoked in the SSLProxy_Analyzer to enable
	 * this SSLv3_Interpreter to start work without having seen the first
	 * handshake record.  This happens, when the client hello is sent in
	 * SSLv2 format and processed by the SSLv2_Interpreter but the further
	 * SSL connection taking place as a SSLv3.0/SSLv3.1 session.
	 *
	 * @param i the new state of the sslAutomaton
	 */
	void SetState(int i);

	static void printStats();

	// Total SSLv3x connections.
	static uint totalConnections;

	// Total SSLv3x connections with <b>complete</b> handshake.
	static uint openedConnections;

	static uint totalRecords; ///< counter for total SSLv3x records seen
	static uint handshakeRecords; ///< counter for SSLv3x handshake records seen
	static uint clientHelloRecords; ///< counter for SSLv3x client hellos seen
	static uint serverHelloRecords; ///< counter for SSLv3x server hellos seen
	static uint alertRecords; ///< counter for SSLv3x alert records seen
	static uint changeCipherRecords; ///< counter for SSLv3x change cipher records seen

	/**Flags for handling the change-cipher-messages and fin-handshake-
	 * messages
	 */
	bool change_cipher_client_seen; ///< whether a client change cipher record was seen
	bool change_cipher_server_seen; ///< whether a server change cipher record was seen
	bool fin_client_seen; ///< whether a client finished handshake message was seen (must immediately follow the client change cipher)
	bool fin_server_seen; ///< whether a server finished handshake message was seen (must immediately follow the server change cipher)

protected:
	static SSLv3_Automaton sslAutomaton; ///< represents the SSLv3.0/SSLv3.1 automaton
	static bool bInited; ///< whether the automaton is already initialised (has to be only done once)
	int currentState; ///< the current state of the SSL automaton in this SSLv3_Interpreter instance

	// uint16 cipherSuite; ///< the cipher spec client and server agreed upon
	SSL_DataBlock* pClientCipherSpecs; ///< the CIPHER-SPECs from the client
	SSL_CipherSpec* pCipherSuite; ///< pointer to the cipher spec definition client and server agreed upon
	uint32 cipherSuiteIdentifier; ///< only used for unknown cipher-specs
	SSL_DataBlock* clientSessionID; ///< the session ID of the client hello record
	SSL_DataBlock* serverSessionID; ///< the session ID for this SSL session

	/**Attributes for cryptographic computations*/
	SSLv3x_Random* clientRandom;
	SSLv3x_Random* serverRandom;
	//SSL_KeyExchangeAlgorithm keyXAlgorithm;
	SSLv3x_ServerRSAParams* serverRSApars;
	SSLv3x_ServerDHParams* serverDHPars;
	SSLv3x_EncryptedPremasterSecret* encryptedPreSecret;
	SSLv3x_ClientDHPublic* clientDHpublic;

	bool helloRequestValid; ///< Whether sending a hello request is valid (normally after handshaking phase)

	/** This method builds the corresponding SSLv3_Endpoints for this SSLv3_Interpreter.
	 * It is called in the SSL_Interpreter's Init() method.
	 */
	void BuildInterpreterEndpoints();

	/** This method initialises the SSL state automaton; sets the states and transitions.
	 * It needs only to be called once for a whole bro. @see SSLDefines.h
	 */
	void BuildAutomaton();

	/** This helper method translates the handshake types included in the SSL handshake
	 * records to the corresponding transition of the SSL automaton. It is invoked within
	 * the DeliverSSLv3_Record(SSLv3_HandshakeRecord*) method.
	 *
	 * @param type the handshake type of the handshake record
	 */
	int HandshakeType2Trans(int type);

	/** This method is used for event generation during the handshaking phase and
	 * generates the connection-attempt, server-reply, connection-established, connection-reused
	 * events dependant on the currentState of the SSL Automaton.
	 * It calls the appropriate fire_* methods of the SSL_Interpreter for this.
	 * The method is called within the the DeliverSSLv3_Record() methods.
	 *
	 * @param rec the SSLv3_Record which is currently processed
	 */
	void GenerateEvents(SSLv3_Record* rec, TableVal* curCipherSuites);

	/** This method analyzes the cipher suites the client and server offer
	 * each other during handshaking phase. It checks, whether it's a 'common'
	 * cipher suite and sets the pCipherSuite attribute according to the
	 * cipher suite client and server agreed on.
	 *
	 * @param s the SSLv3_Endpoint which sent the SSL record with the cipher suite(s) to be analyzed
	 * @param length length of data
	 * @param data pointer to where the cipher suites can be found
	 * @param version SSL version of the SSL record that contained the cipher suite(s)
	 * @return a pointer to a Bro TableVal (of type cipher_suites_list) which contains
	 *	the cipher suites list of the current analyzed record
	 */
	 TableVal* analyzeCiphers(const SSLv3_Endpoint* s, int length, const u_char* data, uint16 version);

};

// ----------------------------------------------------------------------------

/** Class SSLv3_Endpoint is the implementation for SSLv3.0/SSLv3.1 connection
 * endpoints (derived from the abstract class SSL_InterpreterEndpoint).
 *
 * A SSLv3_Endpoint gets completely reassembled ssl records via the method
 * Deliver(), which is invoked in this Endpoint's corresponding SSLProxy_Analyzer.
 * The defragmentation and reassembling already took place in the
 * SSLProxy_Analyzer's SSL_RecordBuilder.
 * The Deliver()-method does some basic weird checks and then calls
 * ProcessMessage() which determines the content type of the ssl record
 * and, dependant on that, creates an instance of the appropriate SSLv3_Record.
 * This is passed on to this endpoint's corresponding SSLv3_Interpreter via
 * the DeliverSSLv3_Record()-method.
 */
class SSLv3_Endpoint : public SSL_InterpreterEndpoint {
public:
	/** The constructor takes the corresponding SSL_Interpreter as argument.
	 * is_orig sets this endpoint as originator of the connection (1), and
	 * responder otherwise (0).
	 *
	 * @param interpreter the SSL_Interpreter this endpoint is bound to.
	 * @param is_orig whether this endpoint is the originator (1) of the
	 *			connection or not (0).
	 */
	SSLv3_Endpoint(SSL_Interpreter* interpreter, int is_orig);
	virtual ~SSLv3_Endpoint();

	/** This method is invoked by this endpoint's corresponding
	 * SSLProxy_Analyzer and receives completely reassembled SSL
	 * records (by the data argument).
	 *
	 * @param t time is always 0 (former: when the segment was received
	 *	by bro (?))
	 * @param len length of SSL record
	 * @param data content of SSL record
	 */
	void Deliver(int len, const u_char* data);

protected:
	uint16 sslVersion; ///< holds the version of the just delivered SSL record
	uint16 currentMessage_length; ///< the length of the just delivered SSL record

	/** This method extracts the content type of the SSL record passed
	 * in the first parameter.
	 *
	 * @param data the SSL record
	 * @param len length of the record
	 * @return SSL3_1_ContentType of SSL record
	 */
	SSL3_1_ContentType ExtractContentType(const u_char* data, int len);

	/** This method determines the version of the SSL record passed to it.
	 * It sets the field sslVersion of this endpoint an is called within
	 * the method ProcessMessage().
	 *
	 * @param data the SSL record
	 * @param len length of the record
	 * @return 0 if version is NOT 3.0/3.1, 1 otherwise
	*/
	int ExtractVersion(const u_char* data, int len);

	/** This method processes a complete SSL record. It
	 * determines the content type of the SSL record
	 * (handshake, alert, change-cipher-spec, application),
	 * cuts away the SSL record layer header and generates
	 * the appropriate SSLv3_Record. Then it calls the SSLv3_Record's
	 * Deliver() method, which manages the delivery of the record
	 * to the corresponding SSLv3_Interpreter
	 *
	 * @param data the complete SSL record
	 * @param len data's (record's) length
	 */
	void ProcessMessage(const u_char* data, int len);
};

// ----------------------------------------------------------------------------

// Offsets are now relative to the end of the SSL record layer header
#define SSL3_1_CHANGE_CIPHER_TYPE_OFFSET (SSL3_1_HEADERLENGTH - 5)
#define SSL3_1_ALERT_LEVEL_OFFSET (SSL3_1_HEADERLENGTH - 5)
#define SSL3_1_ALERT_DESCRIPTION_OFFSET (SSL3_1_HEADERLENGTH - 4)
#define SSL3_1_SESSION_ID_LENGTH_OFFSET 38
#define SSL3_1_SESSION_ID_OFFSET 39

/** This class is an abstract base class for the four different
 * SSLv3.0/SSLv3.1 record types (handshake, alert, change-cipher-spec,
 * application).
 *
 * It contains a pointer to the data of the SSL record <b>without</b>
 * the SSL record layer header, it's length and the version information, which
 * was present in the now cut away SSL record layer header.
 *
 * (Note: the version field of the SSL record layer header may differ from
 * the version of the record format that was used when sending the record.
 * (e.g. a client may send a SSLv2 record including
 * a version field containing 3.1 (for SSLv3.1) to show, that he supports
 * version 3.1.))
 *
 * Every subclass of SSLv3_Record implements the Deliver() method, which
 * manages the delivery of the record to the corresponding SSLv3_Interpreter.
 * Instances of SSLv3_Record (resp. it's subclasses) are created within
 * the ProcessMessage() method of a SSLv3_Endpoint.
 * */
class SSLv3_Record : public BroObj{
public:
	/** The constructor gets a pointer to the SSL record without the
	 * record layer header, it's length, the version information
	 * contained in the record layer header and a pointer to the
	 * SSLv3_Endpoint that created this instance of SSLv3_Record.
	 *
	 * @param data pointer to the SSL record without record layer header
	 * @param data's length
	 * @param version version information contained in the SSL record layer header
	 * @param e the SSLv3_Endpoint that created this instance
	 */
	SSLv3_Record(const u_char* data, int len, uint16 version,
			SSLv3_Endpoint const* e);
	~SSLv3_Record();

	void Describe(ODesc* d) const;

	int GetRecordLength() const;
	const u_char* GetData() const;
	uint16 GetVersion() const;
	SSLv3_Endpoint const* GetEndpoint() const;

	/** This abstract method is implemented by the various SSLv3_Record
	 * subclasses for handshake, alert, change cipher spec and application
	 * records.  It manages the delivery of the SSLv3_Record to the
	 * SSLv3_Interpreter passed as argument.
	 * SSLv3_Records are created within the ProcessMessage() method of the
	 * SSLv3_Endpoint which then calls the just created SSLv3_Records
	 * Deliver() method with it's corresponding SSLv3_Interpreter as
	 * argument which then receives the (evtl. preprocessed) SSLv3_Record
	 * (via the method(s) DeliverSSLv3_Record()).
	 *
	 * @param conn the SSLv3_Interpreter to which this SSLv3_Record should be deliverd
	 */
	virtual void Deliver(SSLv3_Interpreter* conn) =0;

	/** Helper function that converts from 24-bit big endian integer
	 * starting at offset to 32 bit integer in little endian format.
	 *
	 * @param data the ssl-record
	 * @param len length of data (record)
	 * @param offset where the 24 bit big endian starts
	 * @return 32 bit little endian
	 */
	int ExtractInt24(const u_char* data, int len, int offset);

	int recordLength; ///< total length of the SSL record <b>without</b> the record layer header
	const u_char* data; ///< pointer to the SSL record without the record layer header
	SSLv3_Endpoint const* endp; ///< pointer to the SSLv3_Endpoint that created this instance of SSLv3_Record
	uint16 sslVersion; ///< version information of the SSL record layer header
};

// ----------------------------------------------------------------------------

/* This class represents a handshake record used in SSLv3.0/SSLv3.1.
 *
 * Handshake records in SSLv3.0/SSLv3.1 need a special treatment,
 * because it is possible that multiple handshake messages are coalesced into
 * a single SSLv3.0/SSLv3.1 record.
 * I think, this only can happen to
 * handshake records (even RFC2246 page 16 generally talks about all
 * messages of a same content type), because only handshake records
 * have got an own length descriptor within and thus make de-coalescing
 * possible.
 * So when generating a new instance of a SSLv3_HandshakeRecord, it is checked whether there
 * are more handshake records within data.
 * If so, they are put apart and linked together to a chain by using
 * the next-pointer.
 * The Deliver() method takes this into account and delivers every single
 * handshake record one by one to the SSLv3_Interpreter.
 */
class SSLv3_HandshakeRecord : public SSLv3_Record{
public:
	SSLv3_HandshakeRecord(const u_char* data, int len, uint16 version,
				SSLv3_Endpoint const* e);
	~SSLv3_HandshakeRecord();

	int GetType() const;
	int GetLength() const;

	/** This method delivers the SSLv3_HandshakeRecord(s) to the
	 * SSLv3_Interpreter passed as argument. The method follows
	 * the next-pointer and delivers every SSLv3_HandshakeRecord
	 * contained in this list to the SSLv3_Interpreter.
	 *
	 * @param conn the SSLv3_Interpreter to which this SSLv3_HandshakeRecord should be deliverd
	 */
	void Deliver(SSLv3_Interpreter* conn);

	/* This method is invoked within the SSLv3_Interpreter and does lots of
	 * weird and consistency checks on a client hello SSL handshake record.
	 *
	 * @return 0 if further processing of this client hello is not
	 * possible due to inconsistency and 1 otherwise.
	 */
	int checkClientHello();

	/* This method is invoked within the SSLv3_Interpreter and does lots of
	 * weird and consistency checks on a server hello SSL handshake record.
	 *
	 * @return 0 if further processing of this server hello is not
	 * possible due to inconsistency and 1 otherwise.
	 */
	int checkServerHello();

	int type;	///< holds the handshake type of the handshake record (first byte)
	int length;	///< holds the length of this handshake record (which is needed due to coalesced handshake messages)

private:
	SSLv3_HandshakeRecord* next;	///< pointer to the next ssl handshake record if they are coalesced into a single record

	SSLv3_HandshakeRecord* GetNext();
};

// ----------------------------------------------------------------------------

/** This class represents an alert record used in SSLv3.0/SSLv3.1.
 *
 * description holds the SSL alert description and level the alert level.
 */
class SSLv3_AlertRecord : public SSLv3_Record {
public:
	SSLv3_AlertRecord(const u_char* data, int len, uint16 version,
				SSLv3_Endpoint const* e);
	~SSLv3_AlertRecord();

	int GetDescription() const;
	int GetLevel() const;

	/** This method delivers the SSLv3_AlertRecord to the SSLv3_Interpreter passed as
	 * argument.
	 *
	 * @param conn the SSLv3_Interpreter to which this SSLv3_AlertRecord should be deliverd
	 */
	void Deliver(SSLv3_Interpreter* conn);

	int description;	///< holds the alert description
	int level;	///< holds the alert level
};

// ----------------------------------------------------------------------------

/** This class represents a change cipher record used in SSLv3.0/SSLv3.1.
 *
 *  type holds the change cipher type used (currently only 1 is valid (rfc 2246))
 */
class SSLv3_ChangeCipherRecord : public SSLv3_Record{
public:
	SSLv3_ChangeCipherRecord(const u_char* data, int len, uint16 version,
				SSLv3_Endpoint const* e);
	~SSLv3_ChangeCipherRecord();
	int GetType() const;

	/** This method delivers the SSLv3_ChangeCipherRecord to the
	 * SSLv3_Interpreter passed as argument.
	 *
	 * @param conn the SSLv3_Interpreter to which this
	 * SSLv3_ChangeCipherRecord should be delivered
	 */
	void Deliver(SSLv3_Interpreter* conn);

	int type;	///< holds the change cipher type
};

// ----------------------------------------------------------------------------

/** This class represents an application record used in SSLv3.0/SSLv3.1.
 */
class SSLv3_ApplicationRecord : public SSLv3_Record {
public:
	SSLv3_ApplicationRecord(const u_char* data, int len, uint16 version,
				SSLv3_Endpoint const* e);
	~SSLv3_ApplicationRecord();

	/** This method delivers the SSLv3_ApplicationRecord to the
	 * SSLv3_Interpreter passed as argument.
	 *
	 * @param conn the SSLv3_Interpreter to which this
	 * SSLv3_ApplicationRecord should be deliverd
	 */
	void Deliver(SSLv3_Interpreter* conn);
};

#endif
