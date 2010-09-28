// $Id: SSLProxy.h 5952 2008-07-13 19:45:15Z vern $

#ifndef SSLPROXY_H
#define SSLPROXY_H

#include "TCP.h"
#include "SSLInterpreter.h"
#include "binpac_bro.h"

// --- forward declarations ---------------------------------------------------

class SSL_Interpreter;
class SSL_RecordBuilder;
class Contents_SSL;

// --- class SSL_DataBlock ----------------------------------------------------

/*!
 * \brief This class is used to store a block of data on the heap, which is
 *        allocated and copied by the constructor, and freed by the destructor.
 *
 * It is mainly used by the SSL_RecordBuilder to store the received data. To
 * reduce heap operations (HeapOps), which can be quite expensive, it is
 * possible to let the constructor allocate a minimum heap block size. The
 * class members keep track of how much data has been allocated and how much of
 * it has been used. Plus, there's a pointer to the next SSL_DataBlock, for
 * easy creation of a single-linked list.
 */

class SSL_DataBlock {
public:
	SSL_DataBlock(const u_char* data, int len, int min_len = 0);

	int len;	///< The <b>used</b> size of the reserved heap block.
	int size;	///< The <b>allocated</b> size of the reserved heap block.
	u_char* data;	///< Pointer to the allocated heap block.
	SSL_DataBlock* next;	///< Pointer to the next SSL_Datablock in the chain.

	/*!
	 * The destructor will free the allocated data block.
	 */
	~SSL_DataBlock() { delete [] data; }

	void toStream(FILE* stream) const;
	char* toString() const;
};

// --- class SSL_RecordBuilder ------------------------------------------------

/*!
 * \brief This class is used to reassemble SSL records from a stream of data.
 *
 * It supports both SSLv2 and SSLv3 record formats at the same time. The record
 * builder has been designed to be robust, efficient and hard to attack. To add
 * a segments of data, call addSegment(). Whenever a SSL record has been
 * reassembled, the DoDeliver() function of the corresponding Contents_SSL
 * will be called.
 *
 * Two forms of attack have been taken into consideration:
 * -# The "fake size" attack, where the actual size of the SSL record is much
 *    smaller then the size given in the record header. This way, an attacker
 *    could force Bro to allocate a huge amount of memory and make it crash.
 * -# The "small fragment" attack, where an attacker sends huge SSL records
 *    in very small (1 byte or so) TCP segments. This could lead to a huge
 *    amount of very small memory blocks allocated by Bro. After the last byte
 *    of an SSL record has been received, all allocated blocks have to be
 *    freed. Freeing something like 32K blocks of memory can be quite expensive,
 *    so packet drops may occur, which could prevent Bro from detecting an
 *    attacker.
 *
 * The current implementation always allocates a minimum size of data on the
 * heap, which is MIN_ALLOC_SIZE. The processed SSL record fragments are stored
 * in a single-linked list of type SSL_DataBlock.
 *
 * The following assumptions are made:
 * - neededSize <= min( expectedSize )
 * - neededSize <= MIN_ALLOC_SIZE, so the data needed to determine the SSL
 *   record version fits in one SSL_DataBlock
 */

class SSL_RecordBuilder {
public:
	SSL_RecordBuilder(Contents_SSL* sslEndpoint);
	~SSL_RecordBuilder();

	static const uint MIN_ALLOC_SIZE = 16;	///< min. size of memory to alloc
	static const int MIN_FRAGMENT_SIZE = 100;	///< min. size of a middle TCP Segment
	static uint maxAllocCount;	///< max. number of allocated data blocks for an instance of a reassembler
	static uint maxFragmentCount;	///< max. number of fragments for a ssl record
	static uint fragmentedHeaders;	///< counter for the number of fragmented headers (header=neededSize)

	bool addSegment(const u_char* data, int length);

	/*!
	 * Calls this method to see if there's currently data in the
	 * record builder pending.
	 * \return true if there's data pending, false otherwise
	 */
	bool isDataPending() { return hasPendingData; };

protected:
	u_char* assembleBlocks(const u_char* data, int length);
	int analyzeSSLRecordFormat(const u_char* data, int length);
	bool computeExpectedSize (const u_char* data, int length);
	void addData(const u_char* data, int length);

	SSL_DataBlock* head;	///< pointer to the first element in the linked list of SSL_DataBlocks
	SSL_DataBlock* tail;	///< pointer to the last element in the linked list of SSL_DataBlocks
	Contents_SSL*  sslEndpoint;	///< pointer to the containing Contents_SSL
	int  expectedSize;	///< expected size of SSLv2 record including header
	int  currentSize;	///< current bytes stored in data blocks (that is, processed size of actual record)
	int  neededSize;	///< min. size in bytes so that the length of the current record can be determinded
	bool hasPendingData;	///< true if there's data following in the current tcp segment
	uint fragmentCounter;	///< counter for the number of tcp segments for the current record
};


// --- class SSLProxy_Analyzer ----------------------------------------------

/** This class represents an SSL_Connection with two SSL_ConnectionEndpoints.
 * Note, that this class acts as a proxy, because there are different versions
 * of the SSL protocol in use and you don't know in advance which SSL version
 * really will be used. This depends on the first two messages of the SSL handshake
 * process. Because Bro offers no possibility for switching connections we
 * decided only to inherit this proxy from TCP_Connection.
 * The different SSL versions are implemented in classed derived from
 * SSL_Interpreter/SSL_InterpreterEndpoint and so, we can easily switch the flow
 * of data to the appropriate SSL Interpreter.
 * Currently, we support SSL Version 2.0 and 3.0/3.1(TLS)(@see SSLv2_Interpreter and @see
 * SSLv3_Interpreter).
 * This class holds an instance of both SSLv2- and SSLv3_Interpreter. The version
 * of the SSL that is used for a connection is negotiated within the first
 * two records (SSL messages): client hello and server hello.
 * So after scanning this two records (which is mainly done in @see SSL_RecordBuilder and
 * @see Contents_SSL) and determing the versions, it is clear which
 * SSL version will be used for the succeding SSL records. From now
 * on, they can be directly passed through to the appropriate SSL_Interpreter.
 *
 * FIXME: Now we have a dynamic analyzer framework so this could be restructured.
 */
class SSLProxy_Analyzer: public TCP_ApplicationAnalyzer {
public:
	SSLProxy_Analyzer(Connection* conn);
	virtual ~SSLProxy_Analyzer();

	static uint totalPackets;	///< counter for total ssl packets seen
	static uint totalRecords;	///< counter for total ssl records seen
	static uint nonSSLConnections;	///< counter for connections where we couldn't reassemble a ssl record

	static const bool recordSSLv2Traffic = false;	///< if true, only recording of SSLv2 connections is done (no analysis)

	static bool bInited;

	enum SSL_Versions {
		SSLv20 = 0x0002,
		SSLv30 = 0x0300,
		SSLv31 = 0x0301  // = TLS 1.0
	};

	/* This method is called from the corresponding Contents_SSL to
	 * deliver the data to the SSL_ProxyConnection. It decides which
	 * SSL_Interpreter (Version 2 or Version 3x) gets the record or
	 * directly passes it through, if it's already clear which version
	 * this SSL connection uses.
	 * @param endp the sending endpoint
	 * @param len length of SSL record
	 * @param data the SSL record
	 *
	 * SC mod  - pass a TCP_Contents rather than endpoint in terms of an actual
	 * Contents_SSL.  There is much less overall work to do since we
	 * have already done the assosciation.
	 */
	void NewSSLRecord(Contents_SSL* endp, int len, const u_char* data);

	// Initialises the SSLv2- and SSLv3_Interpreters.
	virtual void Init();

	// This method is used for passing messages to Bro that contain
	// information about weaknesses in the choosen SSL encryption
	// (short keys, unverifyable certificates, ...)
	// @param name the name of the weakness.
	void Weak(const char* name);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new SSLProxy_Analyzer(conn); }

	static bool Available()
		{
		return (ssl_certificate_seen || ssl_certificate ||
			ssl_conn_attempt || ssl_conn_server_reply ||
			ssl_conn_established || ssl_conn_reused ||
			ssl_conn_alert)
			&& ! FLAGS_use_binpac;
		}

	static void printStats();

protected:
	bool bPassThrough;	///< whether it is clear which SSL version the connection will use

	SSL_Interpreter* sSLv2Interpreter;	///< Interpreter for SSL version 2
	SSL_Interpreter* sSLv3xInterpreter;	///< Interpreter for SSL version 3.0 and 3.1
	SSL_Interpreter* sSLInterpreter;	///< Pointer to the interpreter currently in use

	Contents_SSL* sslpeo;
	Contents_SSL* sslper;

	/** Internally called from this class Deliver()-method.
	 * It delivers the data to the correct corresponding
	 * SSL_InterpreterEndpoint.
	 * @param endp the sending endpoint
	 * @param t time, when the segment was received by bro (not used)
	 * @param seq relative sequenze number (from Endpoint::start_seq) (not used)
	 * @param len length of SSL record
	 * @param data the SSL record
	 */
	void DoDeliver(int len, const u_char* data, bool orig);

	// Initialises the dictionary where the SSL cipher specs are stored.
	// It needs only to be called once for a whole bro. @see SSLDefines.h
	void BuildCipherDict();
};

// --- class Contents_SSL ------------------------------------------------

/** This class represents an endpoint of a SSLProxy_Analyzer.
 * It receives the new data (TCP segments) within the Deliver()-method, does
 * some basic checks on the segment and passes it on to the SSL_RecordBuilder,
 * which reassembles the segments into SSL records and determines the
 * versions of the records. If the SSL_RecordBuilder was able to determine
 * the versions of the records it delivers the reassembled records back tho this
 * Contents_SSL by calling the DoDeliver()-method.
 * The Contents_SSL then hands the record over to the corresponding
 * SSLProxy_Analyzer by invoking it's NewSSLRecord()-method.
 *
 * SC mod: change class Contents_SSL: public TCP_EndpointContents
 * to class Contents_SSL: public TCP_Contents
 * this is done since the class uses the Deliver() method to take care of data.
 *
 */
class Contents_SSL: public TCP_SupportAnalyzer {
public:
	/* The constructor builds up and initialises the Contents_SSL.
	 * @param conn the corresponding Connection
	 * @param whether this is the originator
	 */
	Contents_SSL(Connection* conn, bool orig);
	~Contents_SSL();

	int sslRecordVersion;	///< record version of the first SSL record seen (set by SSLProxy_Analyzer and SSL_RecordBuilder)
	uint16 sslVersion;	///< SSL version of the SSL record seen (set by SSL_RecordBuilder)

	/** Via this method, this Contents_SSL receives the
	 * TCP segments.
	 * @param len length of TCP-Segment
	 * @param data content of TCP-Segment
	 * @param orig whether sending endpoint is originator
	 */
	virtual void DeliverStream(int len, const u_char* data, bool orig);

	/** This method is called by the corresponding SSL_RecordBuilder
	 * upon delivering a new reassembled SSL record.
	 * @param len the length of the record
	 * @param data the record
	 */
	void DoDeliver(int len, const u_char* data);

	/* @return whether we have already seen the first record of the connection of this endpoint yet
	 */
	bool VersionRecognized();

	/* @return whether the first record was of SSL version 2.0
	 */
	bool IsSSLv2Record();

	/* @return whether the corresponding SSL_RecordBuilder has pending data
	 */
	bool isDataPending(); // should be inline

	SSL_RecordBuilder* sslRecordBuilder;

protected:
	bool bVersionRecognized;	///< False, if we haven't seen the first record of the connection of this endpoint yet
	bool bIsSSLv2Record;	///< Was the first record of SSL version 2.0
};

#endif
