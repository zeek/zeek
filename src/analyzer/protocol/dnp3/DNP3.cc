//
// DNP3 was initially used over serial links; it defined its own application
// layer, transport layer, and data link layer. This hierarchy cannot be
// mapped to the TCP/IP stack directly. As a result, all three DNP3 layers
// are packed together as a single application layer payload over the TCP
// layer. Each DNP3 packet in the application layer may look like this DNP3
// Packet:
//
//    DNP3 Link Layer | DNP3 Transport Layer | DNP3 Application Layer
//
//    (This hierarchy can be viewed in the Wireshark visually.)
//
// === Background on DNP3
//
// 1. Basic structure of DNP3 Protocol over serial links. This information
//    can be found in detail in
//
//        DNP3 Specification Volume 2, Part 1 Basic, Application Layer
//        DNP3 Specification Volume 4, Data Link Layer
//
//    Traditionally, the DNP3 Application Layer in serial links contains a
//    "DNP3 Application Layer Fragment". The data that is parsed by the end
//    device and then executed. As the "DNP3 Application Layer Fragment" can
//    be long (>255 bytes), it may be trunkcated and carried in different
//    DNP3 Application Layer of more than one DNP3 packets.
//
//    So we may find a long DNP3 Application Layer Fragment to be transmitted in the following
//    format
//
//        DNP3 Packet #1 : DNP3 Link Layer | DNP3 Transport Layer | DNP3 Application Layer #1
//        DNP3 Packet #2 : DNP3 Link Layer | DNP3 Transport Layer | DNP3 Application Layer #2
//        ....
//        DNP3 Packet #n : DNP3 Link Layer | DNP3 Transport Layer | DNP3 Application Layer #n
//
//    So to get the whole DNP3 application layer fragment, we concatenate
//    each DNP3 Application Layer Data into a logic DNP3 Application Layer
//    Fragment:
//
//       DNP3 Application Layer #1 + DNP3 Application Layer #2 + ... + DNP3 Application Layer #n
//
// 2. Packing DNP3 Network Packet into TCP/IP stack
//
// We will call the original DNP3 Link Layer, Transport Layer and Application
// Layer used in serial link as Pseudo Link Layer, Pseudo Transport Layer and
// Pseudo Application Layer.
//
// For a long DNP3 application layer fragment, we may find it transmitted
// over IP network in the following format:
//
//     Network Packet #1 : TCP Header | DNP3 Pseudo Link Layer | DNP3 Pseudo Transport Layer | DNP3
//     Pseudo Application Layer #1 Network Packet #2 : TCP Header | DNP3 Pseudo Link Layer | DNP3
//     Pseudo Transport Layer | DNP3 Pseudo Application Layer #2
//     ....
//     Network Packet #n : TCP Header | DNP3 Pseudo Link Layer | DNP3 Pseudo Transport Layer | DNP3
//     Pseudo Application Layer #n
//
// === Challenges of Writing DNP3 Analyzer on Binpac ===
//
// The detailed structure of the DNP3 Link Layer is:
//
//     0x05 0x64 Len Ctrl Dest_LSB Dest_MSB Src_LSB Src_MSB CRC_LSB CRC_MSB
//
//     Each field is a byte; LSB: least significant byte; MSB: most significant byte.
//
//     "Len" indicates the length of the byte stream right after this field
//     (excluding CRC fields) in the current DNP3 packet.
//
// Since "Len" is of size one byte, the largest length it can represent is
// 255 bytes. The larget DNP3 Application Layer size is "255 - 5 + size of
// all CRC fields". "minus 5" is coming from the 5 bytes after "Len" field in
// the DNP3 Link Layer, i.e. Ctrl Dest_LSB Dest_MSB Src_LSB Src_MSB Hence,
// the largest size of a DNP3 Packet (DNP3 Data Link Layer : DNP3 Transport
// Layer : DNP3 Application Layer) can only be 292 bytes.
//
// The "Len" field indicates the length of of a single chunk of DNP3 Psuedo
// Application Layer data instead of the whole DNP3 Application Layer
// Fragment. However, we can not know the whole length of the DNP3
// Application Layer Fragment (which Binpac would normally need) until all
// chunks of Pseudo Application Layer Data are received.
//
// We hence exploit the internal flow_buffer class used in Binpac to buffer
// the application layer data until all chunk are received, which does
// require a bit of internal knowledge of the generated code.
//
// The binpac analyzer parses the DNP3 Application Layer Fragment. However,
// we manually add the original Pseudo Link Layer data as an additional
// header before the DNP3 Application Fragment. This helps to know how many
// bytes are in the current chunk of DNP3 application layer data (not the
// whole Application Layer Fragment).
//
// Graphically, the procedure is:
//
// DNP3 Packet :  DNP3 Pseudo Data Link Layer : DNP3 Pseudo Transport Layer : DNP3 Pseudo
// Application Layer
//                                   ||                                    ||
//                                   || (length field)                     || (original payload byte
//                                   stream)
//                                   \/                                    \/
//                DNP3 Additional Header              :                  Reassembled DNP3 Pseudo
//                Application Layer Data
//                                                   ||
//                                                   \/
//                                            Binpac DNP3 Analyzer

#include "zeek/analyzer/protocol/dnp3/DNP3.h"

#include "zeek/Reporter.h"
#include "zeek/analyzer/protocol/dnp3/events.bif.h"

constexpr unsigned int PSEUDO_LENGTH_INDEX = 2; // index of len field of DNP3 Pseudo Link Layer
constexpr unsigned int PSEUDO_CONTROL_FIELD_INDEX =
	3; // index of ctrl field of DNP3 Pseudo Link Layer
constexpr unsigned int PSEUDO_TRANSPORT_INDEX = 10; // index of DNP3 Pseudo Transport Layer
constexpr unsigned int PSEUDO_APP_LAYER_INDEX = 11; // index of first DNP3 app-layer byte.
constexpr unsigned int PSEUDO_TRANSPORT_LEN = 1; // length of DNP3 Transport Layer
constexpr unsigned int PSEUDO_LINK_LAYER_LEN = 8; // length of DNP3 Pseudo Link Layer

namespace zeek::analyzer::dnp3
	{
namespace detail
	{

bool DNP3_Base::crc_table_initialized = false;
unsigned int DNP3_Base::crc_table[256];

DNP3_Base::DNP3_Base(analyzer::Analyzer* arg_analyzer)
	{
	analyzer = arg_analyzer;
	interp = new binpac::DNP3::DNP3_Conn(analyzer);

	ClearEndpointState(true);
	ClearEndpointState(false);

	if ( ! crc_table_initialized )
		PrecomputeCRCTable();
	}

DNP3_Base::~DNP3_Base()
	{
	delete interp;
	}

bool DNP3_Base::ProcessData(int len, const u_char* data, bool orig)
	{
	Endpoint* endp = orig ? &orig_state : &resp_state;

	while ( len )
		{
		if ( endp->in_hdr )
			{
			// We're parsing the DNP3 header and link layer, get that in full.
			int res = AddToBuffer(endp, PSEUDO_APP_LAYER_INDEX, &data, &len);

			if ( res == 0 )
				return true;

			if ( res < 0 )
				return false;

			// The first two bytes must always be 0x0564.
			if ( endp->buffer[0] != 0x05 || endp->buffer[1] != 0x64 )
				{
				analyzer->Weird("dnp3_header_lacks_magic");
				return false;
				}

			// Make sure header checksum is correct.
			if ( ! CheckCRC(PSEUDO_LINK_LAYER_LEN, endp->buffer,
			                endp->buffer + PSEUDO_LINK_LAYER_LEN, "header") )
				{
				analyzer->AnalyzerViolation("broken_checksum");
				return false;
				}

			// If the checksum works out, we're pretty certainly DNP3.
			analyzer->AnalyzerConfirmation();

			// DNP3 packets without transport and application
			// layers can happen, we ignore them.
			if ( (endp->buffer[PSEUDO_LENGTH_INDEX] + 3) == (char)PSEUDO_LINK_LAYER_LEN )
				{
				ClearEndpointState(orig);
				return true;
				}

			// Double check the direction in case the first
			// received packet is a response.
			u_char ctrl = endp->buffer[PSEUDO_CONTROL_FIELD_INDEX];

			if ( orig != (bool)(ctrl & 0x80) )
				analyzer->Weird("dnp3_unexpected_flow_direction");

			// Update state.
			endp->pkt_length = endp->buffer[PSEUDO_LENGTH_INDEX];
			endp->tpflags = endp->buffer[PSEUDO_TRANSPORT_INDEX];
			endp->in_hdr = false; // Now parsing application layer.

			// For the first packet, we submit the header to
			// BinPAC.
			if ( ++endp->pkt_cnt == 1 )
				interp->NewData(orig, endp->buffer, endp->buffer + PSEUDO_LINK_LAYER_LEN);
			}

		if ( ! endp->in_hdr )
			{
			if ( endp->pkt_length <= 0 )
				{
				analyzer->Weird("dnp3_negative_or_zero_length_link_layer");
				return false;
				}

			// We're parsing the DNP3 application layer, get that
			// in full now as well. We calculate the number of
			// raw bytes the application layer consists of from
			// the packet length by determining how much 16-byte
			// chunks fit in there, and then add 2 bytes CRC for
			// each.
			int n = PSEUDO_APP_LAYER_INDEX + (endp->pkt_length - 5) +
			        ((endp->pkt_length - 5) / 16) * 2 +
			        2 * (((endp->pkt_length - 5) % 16 == 0) ? 0 : 1) - 1;

			int res = AddToBuffer(endp, n, &data, &len);

			if ( res == 0 )
				return true;

			if ( res < 0 )
				return false;

			// Parse the application layer data.
			if ( ! ParseAppLayer(endp) )
				return false;

			// Done with this packet, prepare for next.
			endp->buffer_len = 0;
			endp->in_hdr = true;
			}
		}

	return true;
	}

int DNP3_Base::AddToBuffer(Endpoint* endp, int target_len, const u_char** data, int* len)
	{
	if ( ! target_len )
		return 1;

	if ( *len < 0 )
		{
		reporter->AnalyzerError(analyzer, "dnp3 negative input length: %d", *len);
		return -1;
		}

	if ( target_len < endp->buffer_len )
		{
		reporter->AnalyzerError(analyzer, "dnp3 invalid target length: %d - %d", target_len,
		                        endp->buffer_len);
		return -1;
		}

	int to_copy = min(*len, target_len - endp->buffer_len);

	if ( endp->buffer_len + to_copy > MAX_BUFFER_SIZE )
		{
		reporter->AnalyzerError(analyzer, "dnp3 buffer length exceeded: %d + %d", endp->buffer_len,
		                        to_copy);
		return -1;
		}

	memcpy(endp->buffer + endp->buffer_len, *data, to_copy);
	*data += to_copy;
	*len -= to_copy;
	endp->buffer_len += to_copy;

	if ( endp->buffer_len == target_len )
		return 1;

	return 0;
	}

bool DNP3_Base::ParseAppLayer(Endpoint* endp)
	{
	bool orig = (endp == &orig_state);
	binpac::DNP3::DNP3_Flow* flow = orig ? interp->upflow() : interp->downflow();

	u_char* data = endp->buffer +
	               PSEUDO_TRANSPORT_INDEX; // The transport layer byte counts as app-layer it seems.
	int len = endp->pkt_length - 5;

	// DNP3 Packet :  DNP3 Pseudo Link Layer | DNP3 Pseudo Transport Layer | DNP3 Pseudo Application
	// Layer DNP3 Serial Transport Layer data is always 1 byte. Get FIN FIR seq field in transport
	// header. FIR indicate whether the following DNP3 Serial Application Layer is first chunk of
	// bytes or not. FIN indicate whether the following DNP3 Serial Application Layer is last chunk
	// of bytes or not.

	int is_first = (endp->tpflags & 0x40) >> 6; // Initial chunk of data in this packet.
	int is_last = (endp->tpflags & 0x80) >> 7; // Last chunk of data in this packet.

	int transport = PSEUDO_TRANSPORT_LEN;

	int i = 0;
	while ( len > 0 )
		{
		int n = min(len, 16);

		// Make sure chunk has a correct checksum.
		if ( ! CheckCRC(n, data, data + n, "app_chunk") )
			return false;

		if ( data + n >= endp->buffer + endp->buffer_len )
			{
			reporter->AnalyzerError(analyzer, "dnp3 app layer parsing overflow %d - %d",
			                        endp->buffer_len, n);
			return false;
			}

		// Pass on to BinPAC.
		flow->flow_buffer()->BufferData(data + transport, data + n);
		transport = 0;

		data += n + 2;
		len -= n;
		}

	if ( is_first )
		endp->encountered_first_chunk = true;

	if ( ! is_first && ! endp->encountered_first_chunk )
		{
		// We lost the first chunk.
		analyzer->Weird("dnp3_first_application_layer_chunk_missing");
		return false;
		}

	if ( is_last )
		{
		flow->flow_buffer()->FinishBuffer();
		flow->FlowEOF();
		ClearEndpointState(orig);
		}

	return true;
	}

void DNP3_Base::ClearEndpointState(bool orig)
	{
	Endpoint* endp = orig ? &orig_state : &resp_state;
	binpac::DNP3::DNP3_Flow* flow = orig ? interp->upflow() : interp->downflow();

	endp->in_hdr = true;
	endp->encountered_first_chunk = false;
	endp->buffer_len = 0;
	endp->pkt_length = 0;
	endp->tpflags = 0;
	endp->pkt_cnt = 0;
	}

bool DNP3_Base::CheckCRC(int len, const u_char* data, const u_char* crc16, const char* where)
	{
	unsigned int crc = CalcCRC(len, data);

	if ( crc16[0] == (crc & 0xff) && crc16[1] == (crc & 0xff00) >> 8 )
		return true;

	analyzer->Weird(util::fmt("dnp3_corrupt_%s_checksum", where));
	return false;
	}

void DNP3_Base::PrecomputeCRCTable()
	{
	for ( unsigned int i = 0; i < 256; i++ )
		{
		unsigned int crc = i;

		for ( unsigned int j = 0; j < 8; ++j )
			{
			if ( crc & 0x0001 )
				crc = (crc >> 1) ^ 0xA6BC; // Generating polynomial.
			else
				crc >>= 1;
			}

		crc_table[i] = crc;
		}
	}

unsigned int DNP3_Base::CalcCRC(int len, const u_char* data)
	{
	unsigned int crc = 0x0000;

	for ( int i = 0; i < len; i++ )
		{
		unsigned int index = (crc ^ data[i]) & 0xFF;
		crc = crc_table[index] ^ (crc >> 8);
		}

	return ~crc & 0xFFFF;
	}

	} // namespace detail
DNP3_TCP_Analyzer::DNP3_TCP_Analyzer(Connection* c)
	: DNP3_Base(this), TCP_ApplicationAnalyzer("DNP3_TCP", c)
	{
	}

DNP3_TCP_Analyzer::~DNP3_TCP_Analyzer() { }

void DNP3_TCP_Analyzer::Done()
	{
	TCP_ApplicationAnalyzer::Done();

	Interpreter()->FlowEOF(true);
	Interpreter()->FlowEOF(false);
	}

void DNP3_TCP_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	try
		{
		if ( ! ProcessData(len, data, orig) )
			SetSkip(true);
		}

	catch ( const binpac::Exception& e )
		{
		SetSkip(true);
		throw;
		}
	}

void DNP3_TCP_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	Interpreter()->NewGap(orig, len);
	}

void DNP3_TCP_Analyzer::EndpointEOF(bool is_orig)
	{
	TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	Interpreter()->FlowEOF(is_orig);
	}

DNP3_UDP_Analyzer::DNP3_UDP_Analyzer(Connection* c) : DNP3_Base(this), Analyzer("DNP3_UDP", c) { }

DNP3_UDP_Analyzer::~DNP3_UDP_Analyzer() { }

void DNP3_UDP_Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq,
                                      const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

	try
		{
		if ( ! ProcessData(len, data, orig) )
			SetSkip(true);
		}

	catch ( const binpac::Exception& e )
		{
		SetSkip(true);
		throw;
		}
	}

	} // namespace zeek::analyzer::dnp3
