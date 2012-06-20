// $Id:$
//
// This template code contributed by Kristin Stephens.

#include "DNP3.h"
#include "TCP_Reassembler.h"

//#define P_TEST
#define DEBUG 0
#define COLLECT 0   ///used to collect binaries of DNP3 packets
#define FILE_NAME "/home/hugo/experiment/dnp3/SampleBinary/hl_test.bin"

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
		// so far only one transport segment is considered. So removing first byte will result application level data
		// actually, only one transport segment is needed. different transport segment is put into different TCP packets
	int aTranFir;   // fir field in the transport header
	int aTranFin;   // fin field in the transport header
	int aTranSeq;   // fir field in the transport header
	bool m_orig;   //true -> request; false-> response
	u_char control_field = 0;
	u_char* aTempResult = NULL;
	int aTempFormerLen = 0;
	FILE* file;
	//bool mEncounterFirst = false;

	//printf("test global %d\n", gTest++);
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

/////inject to collect binary if necessary
	#if COLLECT
	file = fopen(FILE_NAME, "ab");
	if(file == NULL)
	{
		printf("file open for binary failed\n");
		return;
	}
	//fwrite("\n", sizeof(char), len, file);
	fwrite(data, sizeof(char), len , file);
	fclose(file);
	#endif

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
		//if(m_orig == true) { printf("ALERT  usually request does not have multiple segments");}
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
///// original processing 
	////TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);
	#ifndef P_TEST
//	#if DEBUG
	//printf("normal processing\n");
//	#endif
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
