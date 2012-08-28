
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

// TODO-Hui: This method is very hard to follow. Please split up into a set
// of separate methods.
void DNP3_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	// TODO-Hui: The parent's DeliverStream should normally be called
	// right away with all the original data. What's the reason that you
	// called it at different locations in your code?
	TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	// TODO-Hui: Please insert a high-level description what the
	// following code is doing.

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
