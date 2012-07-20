// $Id:$
//
// This template code contributed by Kristin Stephens.

#include "DNP3.h"
#include "TCP_Reassembler.h"

#define DEBUG 1

typedef struct ByteStream{
	u_char* mData;
	int length;
} StrByteStream;

StrByteStream gDnp3Data;
int gTest = 1;
bool mEncounterFirst = false;

DNP3_Analyzer::DNP3_Analyzer(Connection* c)
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

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void DNP3_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{

	
	int i;
	int dnp3_i = 0;  // index within the data block
	int dnp3_length = 0;
	u_char* tran_data = 0;  
		// actually, only one transport segment is needed. different transport segment is put into different TCP packets
	int aTranFir;   // fir field in the transport header
	int aTranFin;   // fin field in the transport header
	int aTranSeq;   // fir field in the transport header
	bool m_orig;   //true -> request; false-> response
	u_char control_field = 0;
	u_char* aTempResult = NULL;
	int aTempFormerLen = 0;
	FILE* file;

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
	}
	else
	{
		m_orig = false;
	}

//// get fin fir seq field in transport header
	aTranFir = data[10] & 0x40;
	aTranFir = aTranFir >> 6;
 	aTranFin = data[10] & 0x80;
	aTranFin = aTranFin >> 7;
	aTranSeq = data[10] & 0x3F;
	#if DEBUG
	printf("\n\nhl debug: transport header: Fir %d, Fin %d, Seq, %x\n", aTranFir, aTranFin, aTranSeq);
	#endif
///allocate memory space for the dnp3 only data
	tran_data = (u_char*)malloc(len); // definitely not more than original data payload
	if(tran_data == NULL)
	{
		printf("error!! COuld not alloate memory");	
		return;
	}
//// for debug use just print data payload
	#if DEBUG
        printf("hl debug: len is %d, orig is %x ..", len, m_orig);
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
//   the validation of crc can be set up here in the furutre, now it is ignored
// if this is the first transport segment but not last
	dnp3_i = 0;
	if( (aTranFir == 1) && (aTranFin == 0) ){
		mEncounterFirst = true;
		#if DEBUG
		printf("hl debug  reassembled data");
		#endif
		if(len != 292) { printf("ALERT  length is not 292"); return;}
	
		gDnp3Data.mData = (u_char*)malloc(len);
		if(gDnp3Data.mData == NULL) { printf("ALERT  memory allocation error\n"); return;}
		gDnp3Data.length = len;
		for(i = 0; i < 8; i++){
			gDnp3Data.mData[i]= data[i];  // keep the first 8 bytes
		}
		for(i = 0; i < (len - 10); i++){
			if( (i % 18 != 16) && (i % 18 != 17)        // does not include crc on each data block
				&& ((len - 10 - i) > 2)    // does not include last data block
				&& ( i != 0 ) )             // does not consider first byte, transport layer header
			{
				gDnp3Data.mData[ dnp3_i + 8 ] = data[ i + 10 ];
				dnp3_i++;
			}
		}
		gDnp3Data.length = dnp3_i + 8;
		return;
	}
// if fir and fin are all 0; or last segment (fin is 1)
	dnp3_i = 0;
	if( aTranFir == 0 ){
		if(mEncounterFirst == false){
			printf("ALERT  no first packet is found");
			return; 
		}
		#if DEBUG
		printf("hl debug  reassembled data %x %x %d\n", gDnp3Data.mData[0], gDnp3Data.mData[1], gDnp3Data.length);
		#endif
		aTempFormerLen = gDnp3Data.length;
		if( (aTranFin == 0) && (len != 292) ) { printf("ALERT  length is not 292"); return;}
		//if(m_orig == true) { printf("ALERT  usually request does not have multiple segments");}
		aTempResult = (u_char*)malloc(len + aTempFormerLen);
		if(aTempResult == NULL) { printf("ALERT  memory allocation error\n"); return;}
		for(i = 0; i < aTempFormerLen; i++){
			aTempResult[i] = gDnp3Data.mData[i];
		}
		for(i = 0; i < (len - 10); i++){
			if( (i % 18 != 16) && (i % 18 != 17)        // does not include crc on each data block
				&& ((len - 10 - i) > 2)    // does not include last data block
				&& ( i != 0 ) )             // does not consider first byte, transport layer header
			{
				aTempResult[ dnp3_i + aTempFormerLen ] = data[ i + 10 ];
				dnp3_i++;
			}
		}
		gDnp3Data.length = dnp3_i + aTempFormerLen;
		//free(gDnp3Data.mData);
		gDnp3Data.mData =  aTempResult;
		if( aTranFin == 1){   // if this is the last segment
			mEncounterFirst = false;
			if(gDnp3Data.length >= 65536){ 
				printf("ALERT  current dont supprt such long segments");
				free(gDnp3Data.mData);
				gDnp3Data.length = 0;
				return;
			}
			#if DEBUG
			printf("hl debug final reassembled data %d 0x%x \n", gDnp3Data.length, gDnp3Data.length );
			#endif
			gDnp3Data.mData[2] = (gDnp3Data.length -2) % 0x100;
			gDnp3Data.mData[3] = ( (gDnp3Data.length -2) & 0xFF00) >> 8;
			
			#if DEBUG	
			for(i = 0; i < (gDnp3Data.length); i++){
				printf("%x ", gDnp3Data.mData[i]);
				if( (i % 256) == 255 ) printf("\nNew packet\n");
			}
			printf("\n");
			#endif
			TCP_ApplicationAnalyzer::DeliverStream(gDnp3Data.length, gDnp3Data.mData, m_orig);
        		interp->NewData(m_orig, gDnp3Data.mData, (gDnp3Data.mData) + (gDnp3Data.length) );
			free(gDnp3Data.mData);
			gDnp3Data.length = 0;
		}
		#if DEBUG
		else{
			printf("hl debug partially reassembled data %d 0x%x \n", gDnp3Data.length, gDnp3Data.length);
			for(i = 0; i < (gDnp3Data.length); i++){
				printf("%x ", gDnp3Data.mData[i]);
				//if( (i % 256) == 255 ) printf("\nNew packet\n");
			}
			printf("\n");
		}
		#endif
		
		return;		
	}
// if fir 0 and fin is 1. the last segment
//	dnp3_i = 0;
	

// if fir and fin are all 1
	if(mEncounterFirst == true){
		printf("ALERT  this should happen");
	}
	dnp3_i = 0;
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
	tran_data[3] = 0;   // put ctrl as zero as the high-8bit 
	dnp3_length = dnp3_i + 8;
	#if DEBUG
	printf("dnp3 app data: ");
	for(i = 0; i < (dnp3_i+8); i++)
	{
		printf("%x ", tran_data[i]);
	}
	printf("\n");
	#endif


	TCP_ApplicationAnalyzer::DeliverStream(dnp3_length, tran_data, m_orig);
	////DNP3TCP_Analyzer::DeliverStream(len, data, orig);
	////interp->NewData(orig, data, data + len);
	interp->NewData(m_orig, tran_data, tran_data + dnp3_length);
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
