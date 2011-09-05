// $Id:$
//
// This template code contributed by Kristin Stephens.

#include "DNP3.h"
#include "TCP_Reassembler.h"

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
	int dnp3_i;  // index within the data block
	int dnp3_length = 0;
	u_char* tran_data = 0;  // so far only one transport segment is considered. So removing first byte will result application level data
	bool m_orig;   //true -> request; false-> response
	u_char control_field = 0;
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
        printf("\n\nhl debug: len is %d, orig is %x ..", len, m_orig);
	dnp3_i = 0;
        for(i = 0; i < len; i++)
        {
                printf("%x ", data[i]);
		
        }
        printf("hl debug!\n");
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
	printf("dnp3 app data: ");
	for(i = 0; i < (dnp3_i+8); i++)
	{
		printf("%x ", tran_data[i]);
	}
	printf("\n");
///// original processing 
	//TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);
	TCP_ApplicationAnalyzer::DeliverStream(dnp3_length, tran_data, m_orig);
	//DNP3TCP_Analyzer::DeliverStream(len, data, orig);
	//interp->NewData(orig, data, data + len);
	interp->NewData(m_orig, tran_data, tran_data + dnp3_length);
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
