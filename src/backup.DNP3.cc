
#include "DNP3.h"
#include "TCP_Reassembler.h"

DNP3_Analyzer::DNP3_Analyzer(Connection* c) : TCP_ApplicationAnalyzer(AnalyzerTag::DNP3, c)
	{
	mEncounteredFirst = false;
	interp = new binpac::DNP3::DNP3_Conn(this);
	}

DNP3_Analyzer::~DNP3_Analyzer()
	{
	delete interp;
	}

void DNP3_Analyzer::Done()
	{
	TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

// Hui-Resolve: DNP3 was initially used over serial lines; it defined its own application layer, 
// transport layer, and data link layer. This hierarchy cannot be mapped to the TCP/IP stack 
// directly. As a result, all three DNP3 layers are packed together as a single application layer
// payload over the TCP layer. So each DNP3 packet in the application layer may look like this
// DNP3 Packet :  DNP3 Serial Link Layer : DNP3 Serial Transport Layer : DNP3 Serial Application Layer
//
// When DeliverStream is called, "data" contains DNP3 packets consisting of all original three layers. 
// I use the binpac to write the parser of DNP3 Serial Application Layer instead of the whole application 
// layer payload. The following list explains why I am doing this and other challenges with my resolutions:
//
// 1. A Single DNP3 fragment can be truncated into several DNP3 Serial Application Layer data included under 
// different DNP3 link layer header. As a result, reassembly is needed in some situations to reassemble DNP3 Serial
// Application Layer data to form the complete logical DNP3 fragment. (This is similar to TCP reassembly, but happened in the application layer).
// I find it very challenging to do this reassembly in binpac scripts. So the codes before the calling of DeliverStream
// is to actually (1) extract bytes stream of DNP3 Serial Application Layer from the whole application layer trunk and 
// then deliver them to the binpac analyzer; (2) perform the aformentioned reassembly if necessary. 
//
// 2. The DNP3 Serial Application Layer does not include a length field which indicate the length of this layer.
// This brings challenge to write the binpac scripts. What I am doing is in this DeliverStream function, I extract the
// length field in the DNP3 Serial Link Layer and do some computations to get the length of DNP3 Serial Application Layer and 
// hook the original DNP3 Serial Application Layer data with a additional layer (this is represented by the type of Header_Block) 
// In this way, the DNP3 Serial Application Layer data can be represented properly with binpac script
//
// Graphically, the codes in this functions does:
// DNP3 Packet :  DNP3 Serial Link Layer : DNP3 Serial Transport Layer : DNP3 Serial Application Layer
//                                   ||                                    ||
//                                   || (length field)                     || (original paylad byte stream)         
//                                   \/                                    \/
//                                  Hooked DNP3 Serial Application Layer Data  
//                                                   ||
//                                                   \/
//                                              DNP3 Analyzer
//

// Purpose: Construct "Hooked DNP3 Serial Application Layer Data" from 
// 	DNP3 Packet :  DNP3 Serial Link Layer : DNP3 Serial Transport Layer : DNP3 Serial Application Layer
// as shown in the above figure
// Inputs: len, serial_data, orig is exactaly passed from DNP3_Analyzer::DeliverStream
// Outputs: app_data: the result "Hooked DNP3 Serial Application Layer Data"  
// Return values: 0 - means no errors
//                

void DNP3_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	// The parent's DeliverStream should normally be called
	// right away with all the original data. 
	// However, "data" passed from the parent's DeliverStream include all three serial layers of DNP3 Packets
	// as a result, I need to extract the original serial application layer data and passed to the binpac analyzer
	
	//TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);
	
	
	// If it is not serial protocol data ignore.
	if( data[0] != 0x05 || data[1] != 0x64 )
		return;

	// Double check the orig. in case that the first received traffic is
	// response.
	u_char control_field = data[3];
	bool m_orig = ( (control_field & 0x80) == 0x80 );

	//// Get fin fir seq field in transport header
	int aTranFir = (data[10] & 0x40) >> 6;
	int aTranFin = (data[10] & 0x80) >> 7;
	int aTranSeq = (data[10] & 0x3F);

	// TODO-Hui: What does this comment mean?
	// Parse function code. Temporarily ignore PRM bit
	if ( (control_field & 0x0F) != 0x03 && (control_field & 0x0F) != 0x04 )
		return;

	// TODO-Hui: Again, what does this comment mean? Does this need to be
	// fixed?
	//
	// Process the data payload; extract DNP3 application layer data
	// directly the validation of crc can be set up here in the furutre,
	// now it is ignored if this is the first transport segment but not
	// last

	if ( (aTranFir == 1) && (aTranFin == 0) )
		{
		mEncounteredFirst = true;

		if( len != 292 )
			{
			// The length of the TCP payload containing the first
			// but not last transport segment should be exactly
			// 292 bytes.");
			Weird("dnp3_unexpected_payload_size");
			return;
			}

		gDNP3Data.Reserve(len);

		memcpy(gDNP3Data.mData, data, 8); // Keep the first 8 bytes.

		// TODO-HUi: Insert comment what this is doing.
		int dnp3_i = 0; // Index within the data block.

		for( int i = 0; i < len - 10; i++ )
			{
			if ( (i % 18 != 16) && (i % 18 != 17) // Does not include crc on each data block.
				&& ((len - 10 - i) > 2)       // Does not include last data block.
				&& ( i != 0 ) )               // Does not consider first byte, transport layer header.
				{
				gDNP3Data.mData[dnp3_i + 8] = data[i + 10];
				dnp3_i++;
				}
			}

		gDNP3Data.length = dnp3_i + 8;
		return;
		}

	// If fir and fin are all 0; or last segment (fin is 1).

	if ( aTranFir == 0 )
		{
		if ( ! mEncounteredFirst )
			{
			Weird("dnp3_first_transport_sgement_missing");
			return;
			}

		int aTempFormerLen = gDNP3Data.length;

		// TODO-Hui: The following code is almost identical to the
		// one above. Please factor out into a separate function.

		if ( (aTranFin == 0) && (len != 292) )
			{
			// This is not a last transport segment, so the
			// length of the TCP payload should be exactly 292
			// bytes.
			Weird("unexpected_payload_length");
			return;
			}

		u_char* aTempResult = new u_char[len + aTempFormerLen];
		memcpy(aTempResult, gDNP3Data.mData, aTempFormerLen);

		int dnp3_i = 0;

		for( int i = 0; i < (len - 10); i++ )
			{
			if( (i % 18 != 16) && (i % 18 != 17) // Does not include crc on each data block.
				&& ((len - 10 - i) > 2)      // Does not include last data block.
				&& ( i != 0 ) )              // Does not consider first byte, transport layer header.
				{
				// TODO-HUi: Insert commenty what this is doing.
				// TODO-Hui: Can this overflow?
				aTempResult[dnp3_i + aTempFormerLen] = data[i + 10];
				dnp3_i++;
				}
			}

		delete [] gDNP3Data.mData;
		gDNP3Data.mData = aTempResult;
		gDNP3Data.length = dnp3_i + aTempFormerLen;

		if ( aTranFin == 1 ) // If this is the last segment.
			{
			mEncounteredFirst = false;

			if( gDNP3Data.length >= 65536 )
				{
				// We don't support DNP3 packet with length more than 65536 bytes.
				// TODO-Hui: Why not?
				Weird("dnp3_data_exceeds_65K");
				gDNP3Data.Clear();
				return;
				}

			// TODO-Hui: Please comment.
			gDNP3Data.mData[2] = (gDNP3Data.length - 2) % 0x100;
			gDNP3Data.mData[3] = ((gDNP3Data.length -2) & 0xFF00) >> 8;

			interp->NewData(m_orig, gDNP3Data.mData, gDNP3Data.mData + gDNP3Data.length );

			gDNP3Data.Clear();
			}

		return;
		}

	// If fir 0 and fin is 1, the last segment.

	// If fir and fin are all 1, allocate memory space for the DNP3 only
	// data.
	u_char* tran_data = new u_char[len]; // Definitely not more than original data payload.

	if( mEncounteredFirst == true )
		/// Before this packet, a first transport segment is found
		/// but the finish one is missing.
		Weird("dnp3_missing_finish_packet");
		/// TODO-Hui: Can we continue here?

	// TODO-Hui: Again the same code. Please factor out.

	memcpy(tran_data, data, 8); // Keep the first 8 bytes.

	int dnp3_i = 0;

	for( int i = 0; i < len - 10; i++ )
		{
		if ( (i % 18 != 16) && (i % 18 != 17) // Does not include crc on each data block.
		     && ((len - 10 - i) > 2)       // Does not include last data block.
		     && ( i != 0 ) )               // Does not consider first byte, transport layer header.
			{
			// TODO-HUi: Insert commenty what this is doing.
			// TODO-Hui: Can this overflow?
			tran_data[dnp3_i + 8] = data[i + 10];
			dnp3_i++;
			}
		}

	// Let's print out.
	tran_data[3] = 0;   // Put ctrl as zero as the high-8bit.
	int dnp3_length = dnp3_i + 8;

	interp->NewData(m_orig, tran_data, tran_data + dnp3_length);

	delete [] tran_data;

	// This is for the abnormal traffic pattern such as a a first
	// application packet is sent but no last segment is found.
	mEncounteredFirst = false;
	gDNP3Data.Clear();
}

void DNP3_Analyzer::Undelivered(int seq, int len, bool orig)
	{
	TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	interp->NewGap(orig, len);
	}

void DNP3_Analyzer::EndpointEOF(TCP_Reassembler* endp)
	{
	TCP_ApplicationAnalyzer::EndpointEOF(endp);
	interp->FlowEOF(endp->IsOrig());
	}
