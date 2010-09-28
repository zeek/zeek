// $Id: SSLProxy.cc 6008 2008-07-23 00:24:22Z vern $

#include "SSLProxy.h"
#include "SSLv3.h"
#include "SSLv2.h"

// --- Initalization of static variables --------------------------------------

uint SSLProxy_Analyzer::totalPackets = 0;
uint SSLProxy_Analyzer::totalRecords = 0;
uint SSLProxy_Analyzer::nonSSLConnections = 0;

// --- SSL_DataBlock --------------------------------------------------------

/*!
 * This constructor will allocate a block of data on the heap. If min_len is
 * given, it will determine the minimum size of the new block. The data block
 * referenced by data will be then be copied into the new block.
 *
 * \param data    Pointer to the data which will be copied into the newly
 *                allocated heap block.
 * \param len     Length of the data block to copy.
 * \param min_len The minimum size of data to allocate on the heap, can be omitted.
 */

SSL_DataBlock::SSL_DataBlock(const u_char* arg_data, int len, int min_len)
	{
	// For performance reasons, we allocate at least min_len.
	if ( len < min_len )
		{
		data = new u_char[min_len];
		size = min_len;
		}
	else
		{
		data = new u_char[len];
		this->size = len;
		}

	memcpy(data, arg_data, len);
	this->len = len;
	next = 0;
	}

/*!
 * This is an experimental function which will print the contents of the
 * internal data block in a human-readable fashion to a stream.
 *
 * \param stream The stream for printing the data block to.
 */

void SSL_DataBlock::toStream(FILE* stream) const
	{
	if ( len <= 0 )
		return;

	int idx;
	for ( idx = 0; idx < len-1; ++idx )
		fprintf(stream, "%02X:", data[idx]);

	fprintf(stream, "%02X", data[idx]);
	}

/*!
 * This is an experimental function which will print the contents of the
 * internal data block in a human-readable fashion to a string.
 *
 * \return A string which has to be freed by the caller.
 */

char* SSL_DataBlock::toString() const
	{
	if ( len <= 0 )
		{
		// Currently, we return an empty string if data block is empty.
		char* pDummy = new char[1];
		pDummy[0] = '\0';
		return pDummy;
		}

	char* pString = new char[len*3];
	char* pItx = pString;

	int idx;
	for ( idx = 0; idx < len-1; ++idx )
		{
		sprintf(pItx, "%02X:", data[idx]);
		pItx += 3;
		}

	sprintf(pItx, "%02X", data[idx]);

	return pString;
	}

// --- SSL_RecordBuilder ------------------------------------------------------

uint SSL_RecordBuilder::maxAllocCount = 0;
uint SSL_RecordBuilder::maxFragmentCount = 0;
uint SSL_RecordBuilder::fragmentedHeaders = 0;

/*!
 * The constructor takes an Contents_SSL as parameter. Whenever a SSL
 * record has been reassembled, the DoDeliver() function of this
 * Contents_SSL will be called.
 *
 * \param sslEndpoint The Contents_SSL to which this instance of
 *        SSL_RecordBuilder is bound.
 */

SSL_RecordBuilder::SSL_RecordBuilder(Contents_SSL* arg_sslEndpoint)
	{
	head = tail = 0;
	currentSize = 0;
	expectedSize = -1; // -1 means we don't know yet
	hasPendingData = false;
	fragmentCounter = 0;
	neededSize = 5;  // we need at least 5 bytes to determine version

	sslEndpoint = arg_sslEndpoint;
	}

/*!
 * The destructor frees the chain of SSL_DataBlocks.
 */

SSL_RecordBuilder::~SSL_RecordBuilder()
	{
	// Free the data chain.
	SSL_DataBlock* idx = head;
	SSL_DataBlock* rm;

	while ( idx )
		{
		rm  = idx;
		idx = idx->next;
		delete rm;
		}
	}

/*!
 * This function is the main entry point of the class. Call it with a segment
 * of data to process.
 *
 * \param data   pointer to a data segment that will be reassembled
 * \param length length of the data segment to be reassembled
 *
 * \return true if succesfull, false otherwise
 */

bool SSL_RecordBuilder::addSegment(const u_char* data, int length)
	{
	while ( length > 0 )
		{
		if ( ! head )
			{
			// This is the first fragment of a SSLv2 record,
			// so we analyze the header.

			// Special case: SSL header has been fragmented.
			if ( length < neededSize )
				{
				// We can't determine the record size yet,
				// so we just add this stuff.
				++fragmentedHeaders;
				head = tail = new SSL_DataBlock(data, length,
								MIN_ALLOC_SIZE);
				currentSize += length;
				expectedSize = -1;	// special meaning
				break;
				}

			// Get the expected length of this record.
			if ( ! computeExpectedSize(data, length) )
				return false;

			// Insert weird here replacing assert.
			if ( neededSize > expectedSize )
				{
				sslEndpoint->Weird("SSL_RecordBuilder::addSegment neededSize > expectedSize");
				return false;
				}

			if ( tail != 0 )
				{
				sslEndpoint->Parent()->Weird("SSL_RecordBuilder::addSegment tail != 0");
				return false;
				}

			if ( length > expectedSize )
				{
				// No fragmentation -> no memory-reallocation.
				// We have additional data pending.
				hasPendingData = true;
				sslEndpoint->DoDeliver(expectedSize, data);
				length -= expectedSize;
				data += expectedSize;
				expectedSize = -1;
				}

			else if ( length == expectedSize )
				{
				// No fragmentation -> no memory-reallocation.
				// No additional data pending.
				hasPendingData = false;
				sslEndpoint->DoDeliver(expectedSize, data);
				length -= expectedSize;
				data += expectedSize;
				expectedSize = -1;
				break;
				}
			else

				{
				// First fragment of a record.
				head = tail = new SSL_DataBlock(data, length,
								MIN_ALLOC_SIZE);
				currentSize += length;
				break;
				}

			continue;
			}

		// ! head.
		// We already have some data, so add the current
		// segment special case.
		if ( expectedSize < 0 )
			{
			// We don't know the expected size of
			// this record yet.
			if ( currentSize + length < neededSize )
				{
				// We still can't determine the expected size,
				// so we just add the current fragment.
				addData(data, length);
				break;
				}

			// Now we can determine the expected size the
			// header has been fragmented, so we have to
			// reassemble it.
			uint8 Header[neededSize];
			memcpy(Header, head->data, head->len);
			memcpy(Header + head->len, data, neededSize - head->len);
			if ( ! computeExpectedSize(Header, neededSize) )
				{
				// Since neededSize <= MIN_ALLOC_SIZE,
				// we free only head.
				delete head;
				head = tail = 0;
				return false;
				}

			if ( neededSize > expectedSize )
				{
				sslEndpoint->Parent()->Weird("SSL_RecordBuilder::addSegment neededSize > expectedSize");
				return false;
				}

			// No break, go on with this packet.
			}

		if ( currentSize + length == expectedSize )
			{ // this is exactly the last segment of the record
			hasPendingData = false;

			// Create a continuous data structure and call
			// DoDeliver().
			u_char* pBlock = assembleBlocks(data, length);
			sslEndpoint->DoDeliver(expectedSize, pBlock);
			delete [] pBlock;
			expectedSize = -1;
			break;
			}

		else if ( currentSize + length < expectedSize )
			{ // another (middle) segment
			if ( length <= MIN_FRAGMENT_SIZE )
				sslEndpoint->Parent()->Weird( "SSLProxy: Excessive small TCP Segment!" );

			addData(data, length);
			break;
			}

		else
			{
			// This is the last fragment of the current record,
			// but there's more data in this segment.
			int deltaSize = expectedSize - currentSize;
			hasPendingData = true;

			// Create a continuous data structure and call
			// DoDeliver().
			u_char* pBlock = assembleBlocks(data, deltaSize);
			sslEndpoint->DoDeliver(expectedSize, pBlock);
			delete [] pBlock;
			expectedSize = -1;

			// Process the rest.
			length -= deltaSize;
			data += deltaSize;
			}
		} // while

	return true;
	}

/*!
 * This function is called internally by addSegment(), and add's a new SSL
 * record fragment to the internally used list of SSL_DataBlocks. Note that
 * the data will be copied!
 *
 * \param data   pointer to the data that will be added
 * \param length length of the data that will be added
 */

inline void SSL_RecordBuilder::addData(const u_char* data, int length)
	{
	++fragmentCounter;

	// Check if there's some space left in the last datablock.
	int bytesLeft = tail->size - tail->len;
	if ( bytesLeft > 0 )
		{
		// There's some space left in the last data block.
		if ( bytesLeft >= length )
			{
			// We can store all bytes in the last data block.
			memcpy(tail->data + tail->len, data, length);
			tail->len += length;
			currentSize += length;
			}
		else
			{
			// We cannot store all bytes in the last data block,
			// so we also need to add a new one.
			memcpy(tail->data + tail->len, data, bytesLeft);
			tail->len = tail->size;
			currentSize += length;

			data += bytesLeft;
			length -= bytesLeft;

			tail->next = new SSL_DataBlock(data, length, MIN_ALLOC_SIZE);
			tail = tail->next;
			}
		}

	else
		{
		// Last data block is full.
		tail->next = new SSL_DataBlock(data, length, MIN_ALLOC_SIZE);
		tail = tail->next;
		currentSize += length;
		}
	}

/*!
 * This function is called internally by addSegment(), whenever a SSL record
 * has been fully received. It creates a single data block from the list of
 * SSL record fragments while freeing them.
 *
 * \param data   pointer to the last SSL record fragment
 * \param length size of the last SSL record fragment
 *
 * \return pointer to a data block which contains the reassembled SSL record
 */

u_char* SSL_RecordBuilder::assembleBlocks(const u_char* data, int length)
	{
	// We don't store the last SSL record fragment in a DataBlock,
	// instead we get it directly as parameter.
	u_char* dataptr = new u_char[currentSize + length];
	u_char* nextseg = dataptr;

	SSL_DataBlock* idx = head;
	SSL_DataBlock* rm;
	uint allocCounter = 0;

	while ( idx )
		{
		++allocCounter;
		memcpy(nextseg, idx->data, idx->len);
		nextseg += idx->len;
		rm = idx;
		idx = idx->next;
		delete rm;
		}

	// The last fragment isn't stored in a datablock.
	memcpy(nextseg, data, length);

	// The first and last fragments aren't counted.
	fragmentCounter += 2;

	// Update statistics.
	if ( allocCounter > maxAllocCount )
		maxAllocCount = allocCounter;

	if ( fragmentCounter > maxFragmentCount )
		maxFragmentCount = fragmentCounter;

	fragmentCounter = 0;
	currentSize = 0;
	head = tail = 0;

	return dataptr;
	}

/*!
 * This method is called internally by computeExpectedSize(), when the SSL
 * record format has not been determined yet. It tries to do so by using
 * heuristics, since there's no definitive way to distinguish SSLv2 vs. SSLv3
 * record headers.
 *
 * \param data   pointer to a data block containing the SSL record to analyze
 * \param length length of the SSL record to analyze, has to be >= neededSize!
 *
 * \return
 *         -  2 for SSLv2 record format
 *         -  3 for SSLv3 record format
 *         - -1 if an error occurred
 */

int SSL_RecordBuilder::analyzeSSLRecordFormat(const u_char* data, int length)
	{
	// We have to use heuristics for this one.

	if ( length < neededSize )
		{
		sslEndpoint->Parent()->Weird("SSLProxy: analyzeSSLRecordFormat length < neededSize");
		return -1;
		}

	bool found_ssl3x = 0;
	bool found_ssl2x = 0;

	// SSLv3x-check.
	SSL3_1_ContentType ct = SSL3_1_ContentType(uint8(*data));
	switch ( ct ) {
	case SSL3_1_TYPE_CHANGE_CIPHER_SPEC:
	case SSL3_1_TYPE_ALERT:
	case SSL3_1_TYPE_HANDSHAKE:
	case SSL3_1_TYPE_APPLICATION_DATA:
		{
		sslEndpoint->sslVersion = ((data[1]) << 8) | data[2];
		uint16 v = sslEndpoint->sslVersion;
		if ( v == uint16(SSLProxy_Analyzer::SSLv30) ||
		     v == uint16(SSLProxy_Analyzer::SSLv31) )
			found_ssl3x = true;
		break;
		}
	}

	// SSLv2 check.
	// We look for CLIENT-HELLOs, SERVER-HELLOs and ERRORs.
	const u_char* pContents = data;
	uint offset = 0;
	uint16 size = 0;
	if ( (data[0] & 0x80) > 0 )
		{ // we have a two-byte record header
		offset = 2;
		size = (((data[0] & 0x7f) << 8) | data[1]) + 2;
		}
	else
		{ // we have a three-byte record header
		offset = 3;
		size = (((data[0] & 0x3f) << 8) | data[1]) + 3;
		}
	pContents += offset;

	switch ( SSLv2_MessageTypes(pContents[0]) ) {
	case SSLv2_MT_ERROR:
		if ( size == SSLv2_ERROR_RECORD_SIZE + offset)
			{
			found_ssl2x = true;
			sslEndpoint->sslVersion =
				uint16(SSLProxy_Analyzer::SSLv20);
			}
		break;

	case SSLv2_MT_CLIENT_HELLO:
		{
		sslEndpoint->sslVersion =
			uint16(pContents[1] << 8) | pContents[2];
		uint16 v = sslEndpoint->sslVersion;

		if ( v == SSLProxy_Analyzer::SSLv20 ||
		     v == SSLProxy_Analyzer::SSLv30 ||
		     v == SSLProxy_Analyzer::SSLv31 )
			found_ssl2x = true;
		break;
		}

	case SSLv2_MT_SERVER_HELLO:
		{
		sslEndpoint->sslVersion =
			uint16(pContents[3] << 8) | pContents[4];
		uint16 v = sslEndpoint->sslVersion;

		if ( v == SSLProxy_Analyzer::SSLv20 ||
		     v == SSLProxy_Analyzer::SSLv30 ||
		     v == SSLProxy_Analyzer::SSLv31 )
			found_ssl2x = true;
		break;
		}

	default:
		break;
	}

	// Consistency checks.
	if ( (found_ssl3x || found_ssl2x) == false )
		{
		sslEndpoint->Parent()->Weird("SSLProxy: Could not determine SSL version!");
		return -1;
		}

	if ( (found_ssl3x && found_ssl2x) == true )
		{
		sslEndpoint->Parent()->Weird("SSLProxy: Found ambigous SSL version!");
		return -1;
		}

	if ( found_ssl2x )
		return 2;
	else
		return 3;
	}

/*!
 * This method is called internally by addSegment() to determine the expected
 * size of a SSL record.
 *
 * \param data   pointer to the SSL record to analyze
 * \param length length of the SSL record to analyze
 *
 * \return true if succesfull, false otherwise
 */

bool SSL_RecordBuilder::computeExpectedSize(const u_char* data, int length)
	{
	if ( sslEndpoint->sslRecordVersion < 0 )
		{
		// We don't know the ssl record format yet, so we try
		// to find out.
		sslEndpoint->sslRecordVersion =
			analyzeSSLRecordFormat(data, length);

		if ( sslEndpoint->sslRecordVersion != 2 &&
		     sslEndpoint->sslRecordVersion != 3 )
			// We could not determine the ssl record version.
			return false;
		}

	// Get the expected length of this record.
	if ( sslEndpoint->sslRecordVersion == 2 )
		{
		if ( (data[0] & 0x80) > 0 )
			// We have a two-byte record header.
			expectedSize = (((data[0] & 0x7f) << 8) | data[1]) + 2;
		else
			// We have a three-byte record header.
			expectedSize = (((data[0] & 0x3f) << 8) | data[1]) + 3;
		}

	else if ( sslEndpoint->sslRecordVersion == 3 )
		expectedSize = ((data[3] << 8) | data[4]) + 5;

	if ( expectedSize < neededSize )
		{
		// This should never happen (otherwise: UNTESTED).
		sslEndpoint->Parent()->Weird( "SSLProxy: expectedSize < neededSize in RecordBuilder!" );
		return false;
		}

	return true;
	}


// --- SSL_Connection_Proxy ---------------------------------------------------

bool SSLProxy_Analyzer::bInited = false;

SSLProxy_Analyzer::SSLProxy_Analyzer(Connection* conn)
: TCP_ApplicationAnalyzer(AnalyzerTag::SSL, conn)
	{
	sSLv2Interpreter = new SSLv2_Interpreter(this);
	sSLv3xInterpreter = new SSLv3_Interpreter(this);
	sSLInterpreter = 0;
	bPassThrough = false;
	if ( ! bInited )
		{
		BuildCipherDict();
		bInited = true;
		}

	AddSupportAnalyzer(sslpeo = new Contents_SSL(conn, true));
	AddSupportAnalyzer(sslper = new Contents_SSL(conn, false));
	}

SSLProxy_Analyzer::~SSLProxy_Analyzer()
	{
	delete sSLv2Interpreter;
	delete sSLv3xInterpreter;
	}

void SSLProxy_Analyzer::Init()
	{
	TCP_ApplicationAnalyzer::Init();

	sSLv2Interpreter->Init();
	sSLv3xInterpreter->Init();

	sSLv2Interpreter->Orig()
		->SetProxyEndpoint(sSLv3xInterpreter->Orig()->GetProxyEndpoint());
	sSLv2Interpreter->Resp()
		->SetProxyEndpoint(sSLv3xInterpreter->Resp()->GetProxyEndpoint());
	}

void SSLProxy_Analyzer::BuildCipherDict()
	{
	for ( uint idx = 0; idx < SSL_CipherSpecs_Count; ++idx )
		{
		HashKey h(static_cast<bro_uint_t>(SSL_CipherSpecs[idx].identifier));
		SSL_CipherSpecDict.Insert(&h, &SSL_CipherSpecs[idx]);
		}
	}

void SSLProxy_Analyzer::NewSSLRecord(Contents_SSL* endp,
					int len, const u_char* data)
	{
	// This is to extract only SSLv2 traffic.
	if ( recordSSLv2Traffic )
		{
		uint16 sslVersion = 0;
		if ( (data[0] & 0x80) > 0 )
			// We have a two-byte record header.
			sslVersion = (data[3] << 8) | data[4];
		else
			// We have a three-byte record header.
			sslVersion = (data[4] << 8) | data[5];

		if ( ! endp->IsSSLv2Record() ||
		     sslVersion != SSLProxy_Analyzer::SSLv20 )
			{
			SetSkip(1);
			Conn()->SetRecordPackets(0);
			Conn()->SetRecordContents(0);
			// FIXME: Could do memory cleanup here.
			}
		else
			// No analysis - only recording.
			SetSkip(1);

		return;
		}

	if ( bPassThrough )
		{
		DoDeliver(len, data, endp->IsOrig());
		return;
		}

	if ( ! endp->IsSSLv2Record() )
		{
		// It's TLS or SSLv3, so we are done ...
		sSLInterpreter = sSLv3xInterpreter;
		bPassThrough = true;
		// Tell the other record builder we have SSLv3x.
		endp->sslRecordVersion = 3;
		DoDeliver(len, data, endp->IsOrig());
		}

	else
		{ // we have a SSLv2 record ...
		sSLInterpreter = sSLv2Interpreter;

		// Check whether it's the first or second we've seen ...
		if ( sslpeo->VersionRecognized() &&
		     sslper->VersionRecognized() )
			{
			// Second record we've seen.
			// O.K. Both endpoints recognized the version.
			// So this needs to be an SSLv2-Connection ...
			bPassThrough = true;
			DoDeliver(len, data, endp->IsOrig());
			}

		// First record we see.
		// The next one may be SSLv2 or SSLv3x,
		// we don't know yet ...
		else if ( endp->sslVersion == SSLv20 )
			{
			// The client supports only SSLv2, so we're done.
			bPassThrough = true;
			endp->sslRecordVersion = 2;
			endp->sslVersion = SSLv20;
			DoDeliver(len, data, endp->IsOrig());
			}

		else
			{
			bPassThrough = false;
			DoDeliver(len, data, endp->IsOrig());

			// Transfer the state of the SSLv2-Interpreter
			// to the state of the SSLv3x-Interpreter ...
			if ( ((SSLv2_Interpreter*) sSLInterpreter)->ConnState() == CLIENT_HELLO_SEEN )
				((SSLv3_Interpreter*) sSLv3xInterpreter)->SetState(SSL3_1_STATE_CLIENT_HELLO_SENT);
			}
		}
	}

void SSLProxy_Analyzer::DoDeliver(int len, const u_char* data, bool orig)
	{
	if ( orig )
		sSLInterpreter->Orig()->Deliver(len, data);
	else
		sSLInterpreter->Resp()->Deliver(len, data);
	}

void SSLProxy_Analyzer::printStats()
	{
	printf("SSLProxy_Analyzer::totalPackets = %u\n", totalPackets);
	printf("SSLProxy_Analyzer::totalRecords = %u\n", totalRecords);
	printf("SSLProxy_Analyzer::nonSSLConnections = %u\n", nonSSLConnections);
	}


void SSLProxy_Analyzer::Weak(const char* name)
	{
	if ( ssl_conn_weak )
		Event(ssl_conn_weak, name);
	}

// --- Contents_SSL ------------------------------------------------------

/*!
 * mod Contents_SSL::Contents_SSL( TCP_Endpoint* arg_endpt, int stop_on_gap )
 *	: TCP_Contents( arg_conn, stop_on_gap, punt_on_partial )
 */

Contents_SSL::Contents_SSL(Connection* conn, bool orig)
: TCP_SupportAnalyzer(AnalyzerTag::Contents_SSL, conn, orig)
	{
	sslRecordBuilder = new SSL_RecordBuilder(this);
	bVersionRecognized = false;
	bIsSSLv2Record = false;

	sslRecordVersion = -1;	// -1 means we don't know yet
	sslVersion =  0;	// 0 means we don't know yet
	}

Contents_SSL::~Contents_SSL()
	{
	delete sslRecordBuilder;
	}

bool Contents_SSL::isDataPending()
	{
	return sslRecordBuilder->isDataPending();
	}

void Contents_SSL::DeliverStream(int len, const u_char* data, bool orig)
	{
	TCP_SupportAnalyzer::DeliverStream(len, data, orig);

	TCP_Analyzer* tcp = static_cast<TCP_ApplicationAnalyzer *>(Parent())->TCP();
	assert(tcp);

	if ( tcp->HadGap(orig) || tcp->IsPartial() )
		 return;

	++SSLProxy_Analyzer::totalPackets;

	TCP_Endpoint* endp = orig ? tcp->Orig() : tcp->Resp();

#if 0
	// FIXME: What's this???
	int ack = endp->AckSeq() - endp->StartSeq();
	int top_seq = seq + len;

	if ( top_seq <= ack )
		// There is no new data in this packet.
		return;
#endif

	if ( len <= 0 )
		return;

	// No further processing if we have a partial connection.
	if ( endp->state == TCP_ENDPOINT_PARTIAL ||
	     endp->peer->state == TCP_ENDPOINT_PARTIAL )
		{
		Parent()->SetSkip(1);
		Conn()->SetRecordPackets(0);
		return;
		}

	if ( ! sslRecordBuilder->addSegment(data, len) )
		{
		// The RecordBuilder failed to determine the SSL record version,
		// so we can't analyze this connection any further.
		++SSLProxy_Analyzer::nonSSLConnections;
		Parent()->Weird("SSL: Skipping connection (not an SSL connection?!)!");
		Parent()->SetSkip(1);
	    Conn()->SetRecordPackets(0);
		}
	}

// Called by the RecordBuilder with a complete SSL record.
void Contents_SSL::DoDeliver(int len, const u_char* data)
	{
	++SSLProxy_Analyzer::totalRecords;

	bIsSSLv2Record = sslRecordVersion == 2;
	bVersionRecognized = true;

	((SSLProxy_Analyzer*) Parent())->NewSSLRecord(this, len, data);
	}

bool Contents_SSL::IsSSLv2Record()
	{
	return bIsSSLv2Record;
	}

bool Contents_SSL::VersionRecognized()
	{
	return bVersionRecognized;
	}
