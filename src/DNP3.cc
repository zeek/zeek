// $Id:$
//
// This template code contributed by Kristin Stephens.

#include "DNP3.h"
#include "TCP_Reassembler.h"

//#define P_TEST
#define DEBUG 1

DNP3_Analyzer::DNP3_Analyzer(Connection* c)
//: DNP3TCP_Analyzer(c)
: TCP_ApplicationAnalyzer(AnalyzerTag::Dnp3, c)
	{
	interp = new binpac::Dnp3::Dnp3_Conn(this);
	}

DNP3_Analyzer::~DNP3_Analyzer()
	{
	delete interp;
	}

void DNP3_Analyzer::Done()
	{
	TCP_ApplicationAnalyzer::Done();
	//DNP3TCP_Analyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void DNP3_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{

	
	int i;
	int dnp3_i = 0;  // index within the data block
	int dnp3_length = 0;
	u_char* tran_data = 0;  // so far only one transport segment is considered. So removing first byte will result application level data
	bool m_orig;   //true -> request; false-> response
	u_char control_field = 0;

////used for performance experiment
	u_char p_data[2048] = {0};
	int p_length = 0;
	bool p_orig;
	//u_char* app_data = 0;   // contains dnp3 application layer data
//// if it is not serial protocol data ignore
	if(data[0] != 0x05 || data[1] != 0x64)
	{
		TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);
		return;
	}
//// double check the orig. in case that the first received traffic is response
	control_field = data[3];
	if( (control_field & 0x80) == 0x80 )   //true request
	{
		m_orig = true;
		///parse the 
	}
	else
	{
		m_orig = false;
	}
///allocate memory space for the dnp3 only data
	tran_data = (u_char*)malloc(len); // definitely not more than original data payload
	if(tran_data == NULL)
	{
		printf("error!! COuld not alloate memory");	
		return;
	}
//// for debug use just print data payload
	#if DEBUG
        printf("\n\nhl debug: len is %d, orig is %x ..", len, m_orig);
	dnp3_i = 0;
        for(i = 0; i < len; i++)
        {
                printf("%x ", data[i]);
		
        }
        printf("hl debug!\n");
	#endif
////parse function code. Temporarily ignore PRM bit
	if( (control_field & 0x0F) != 0x03 && (control_field & 0x0F) != 0x04 )
	{
		return;
	}
//// process the data payload; extract dnp3 application layer data directly
//   the validation of crc can be set up here
	for(i = 0; i < 8; i++)
	{
		tran_data[i]= data[i];  // keep the first 8 bytes
	}
	for(i = 0; i < (len - 10); i++)
	{
		if( (i % 18 != 16) && (i % 18 != 17)        // does not include crc on each data block
				&& ((len - 10 - i) > 2)    // does not include last data block
				&& ( i != 0 ) )             // does not consider first byte, transport layer header
		{
			tran_data[ dnp3_i + 8 ] = data[ i + 10 ];
			dnp3_i++;
		}
	}
	///let's print out
	dnp3_length = dnp3_i + 8;
	#if DEBUG
	printf("dnp3 app data: ");
	for(i = 0; i < (dnp3_i+8); i++)
	{
		printf("%x ", tran_data[i]);
	}
	printf("\n");
	#endif
///// original processing 
	////TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);
	#ifndef P_TEST
	#if DEBUG
	printf("normal processing\n");
	#endif
	TCP_ApplicationAnalyzer::DeliverStream(dnp3_length, tran_data, m_orig);
	////DNP3TCP_Analyzer::DeliverStream(len, data, orig);
	////interp->NewData(orig, data, data + len);
	interp->NewData(m_orig, tran_data, tran_data + dnp3_length);
	#else
//// for the performance analysis
	//p_data = {0x5, 0x64, 0x12, 0xc4, 0x64, 0x0, 0x1, 0x0, 0xc5, 0x1, 0x1e, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x9, 0xae};
	p_data[0] = 0x05;p_data[1] = 0x64;p_data[2] = 0x15;p_data[3] = 0xc4;p_data[4] = 0x64;p_data[5] = 0x00;p_data[6] = 0x01;p_data[7] = 0x00;
	p_data[8] = 0xc5;p_data[9] = 0x01;p_data[10] = 0x1e;p_data[11] = 0x00;p_data[12] = 0x00;p_data[13] = 0x00;p_data[14] = 0x00;p_data[15] = 0x01;
	p_data[16] = 0x00;p_data[17] = 0x00;p_data[18] = 0x00;p_data[19] = 0x00; p_data[20] = 0x1e; p_data[21] = 0x00;p_data[22] = 0x06;
	p_length = 23; 
	p_orig = true;
	#if DEBUG 
	printf("performance test\n");
	#endif
//// let me add some extra meaning object head in order to increased packet size
	// p_data[2]  size 
	// p_length whole length
	// 1002 - 1025; 489 - 512; 234 - 257; 105 - 128
	for(i = 0; i < 105; i = i + 3 )
	{
		p_data[23 + i ] = 0x1e;
		p_data[23 + i + 1 ] = 0x00;
		p_data[23 + i + 2 ] = 0x06;
		
	}
	p_length = 23 + 105;
	//  p_data[2] = 0x15; if size > 255, I will hard code it in binpac code

	TCP_ApplicationAnalyzer::DeliverStream(p_length, p_data, p_orig);	
	interp->NewData(p_orig, p_data, p_data + p_length);

	#endif
//// free tran_data
	free(tran_data);
	}

void DNP3_Analyzer::Undelivered(int seq, int len, bool orig)
	{
	}

void DNP3_Analyzer::EndpointEOF(TCP_Reassembler* endp)
	{
	TCP_ApplicationAnalyzer::EndpointEOF(endp);
	//DNP3TCP_Analyzer::EndpointEOF(endp);
	interp->FlowEOF(endp->IsOrig());
	}
