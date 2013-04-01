
#include "DNP3.h"
#include "TCP_Reassembler.h"


#define MAX_PACKET_SIZE_NOCRC 258  // the length of each trunk of DNP3 Pseudo App Layer Data excluding CRC 
#define MAX_PACKET_SIZE_CRC 292    // the length of each trunk of DNP3 Pseudo App Layer Data including CRC
#define PSEUDO_LINK_LEN 8          // the length of DNP3 Pseudo Link Layer
#define PSEUDO_LINK_LEN_EX 9       // the length of DNP3 Pseudo Link Layer that extend len field into 2 bytes
#define LEN_FIELD_INDEX 2          // index of len field of DNP3 Pseudo Link Layer 
#define CRTL_FIELD_INDEX 3         // index of ctrl field of DNP3 Pseudo Link Layer
#define PSEUDO_TRAN_INDEX 10       // index of DNP3 Pseudo Transport Layer 
#define PSEUDO_TRAN_LEN 1          // The length of DNP3 Pseudo Transport Layer

#define DNP3_APP_DATA_BLK 16       // maximum length of a data block in DNP3 Pseudo App Layer
#define CRC_LEN 2                  // length of CRC 
#define CRC_GEN_POLY 0xA6BC        // Generation Polynomial to calculate 16-bit CRC

DNP3_Analyzer::DNP3_Analyzer(Connection* c) : TCP_ApplicationAnalyzer(AnalyzerTag::DNP3, c)
	{
	mEncounteredFirst = false;

	//// precompute CrcTable
	this->DNP3_PrecomputeCRC(DNP3_CrcTable, CRC_GEN_POLY);  
	
	interp = new binpac::DNP3::DNP3_Conn(this);

	upflow_count = 0 ;
	downflow_count = 0 ;
	}

DNP3_Analyzer::~DNP3_Analyzer()
	{

	delete interp;
	mEncounteredFirst = false;
	}

void DNP3_Analyzer::Done()
	{
	
	TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

// DNP3 was initially used over serial links; it defined its own application layer, 
// transport layer, and data link layer. This hierarchy cannot be mapped to the TCP/IP stack 
// directly. As a result, all three DNP3 layers are packed together as a single application layer
// payload over the TCP layer. Each DNP3 packet in the application layer may look like this
// DNP3 Packet:  DNP3 Pseudo Link Layer | DNP3 Pseudo Transport Layer | DNP3 Pseudo Application Layer
// (this hierarchy can be viwed in the Wireshark visually)
//
// Background on DNP3
//
// 1. Basic structure of DNP3 Protocol over serial links, This information can be found in detail in 
//     DNP3 Specification Volum 2, Part 1 Basic, Application Layer
//     DNP3 Specification Volum 4, Data Link Layer
// In history, the DNP3 Application Layer in serial links contains a "DNP3 Application Layer Fragment", the data that is 
// parsed by the end device and is executed. The "DNP3 Application Layer Fragment" can be long (> 255 bytess) 
 // so it can be trunkcated and carried in different DNP3 Pseudo Application Layer of more than one DNP3 packets. 
// 
// So we may find a long DNP3 Application Layer Fragment to be transmitted in the following format
//
// DNP3 Packet #1 : DNP3 Link Layer | DNP3 Transport Layer | DNP3 Application Layer #1
// DNP3 Packet #2 : DNP3 Link Layer | DNP3 Transport Layer | DNP3 Application Layer #2
// ....
// DNP3 Packet #n : DNP3 Link Layer | DNP3 Transport Layer | DNP3 Application Layer #n
// 
// So to get the whole DNP3 application layer fragment, we concatenate each DNP3 Application Layer Data. 
// A logic DNP3 Application Layer Fragment 
//	= DNP3 Application Layer #1 + DNP3 Application Layer #2 + ... + DNP3 Application Layer #n
//
// 2. Packing DNP3 Network Packet into TCP/IP stack
//
// For a long DNP3 application layer fragment, we may find it tramistted 
// over IP network in the following format: 
// Network Packet #1 : TCP Header | DNP3 Pseudo Link Layer | DNP3 Pseudo Transport Layer | DNP3 Pseudo Application Layer #1
// Network Packet #2 : TCP Header | DNP3 Pseudo Link Layer | DNP3 Pseudo Transport Layer | DNP3 Pseudo Application Layer #2
// ....
// Network Packet #n : TCP Header | DNP3 Pseudo Link Layer | DNP3 Pseudo Transport Layer | DNP3 Pseudo Application Layer #n
//
//
//  **  Challenges of Writing DNP3 Analyzer on Binpac  **
//
///Note: The detailed structure of the DNP3 Link Layer is: 
// 0x05 0x64 Len Ctrl Dest_LSB Dest_MSB Src_LSB Src_MSB CRC_LSB CRC_MSB 
//       (each field is a byte; LSB: least significant byte; MSB: Most significatn Byte )
// "Len" field indicates the length of the byte stream right after this field (execluding CRC fields) in this current 
//  DNP3 packet 
// Since "Len" field is of size one byte, so largest length it can represent is 255 bytes. 
// The larget DNP3 Application Layer size is (255 - 5 + size of all CRC fields). minus 5 is coming from
// the 5 bytes after "Len" field in the DNP3 Link Layer, i.e. Ctrl Dest_LSB Dest_MSB Src_LSB Src_MSB
// Through calculation, the largest size of 
// a DNP3 Packet (DNP3 Data Link Layer : DNP3 Transport Layer : DNP3 Application Layer) can only be 
//  292 bytes. 
// 
// THe "Len" field indicate the length of of a single trunk of DNP3 Psuedo Application Layer data instead of
// the whole DNP3 Application Layer Fragment. Due to historical reason, we could not know the whole length 
// of the DNP3 Application Layer Fragment, until all trunks of Pseudo Application Layer Data are received.
// I exploit the flow_buffer class used in Binpac to buffer the application layer data until all trunks are 
// received. The trick that I used require in-depth understanding on how Binpac parse the application layer data 
// and perform incremental parsing. 
// The codes that exploit flow_buffer class to buffer the application layer data is included in DNP3_ProcessData
// class.  
//


void DNP3_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{

	//printf("\nEntering Deliverstream\n");
	TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);
	//int newFrame = 0;

	//int result = 0;
	
	//// Checkec the CRC values included in the DNP3 packets
	DNP3_CheckCRC(len, data);

	DNP3_ProcessData(len, data);
	return ;
	
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

// I wrote binpac analyzer to parse DNP3 Application Layer Fragment
// However, I added the original Pseudo Link Layer data before the DNP3 Application Fragment.
// This can help me to know how many bytes are in the current trunk of DNP3 application layer data (not
// the whole Application Layer Fragment)
//
// Graphically, the procedure is:
// DNP3 Packet :  DNP3 Pseudo Data Link Layer : DNP3 Pseudo Transport Layer : DNP3 Pseudo Application Layer
//                                   ||                                    ||
//                                   || (length field)                     || (original paylad byte stream)         
//                                   \/                                    \/
//                DNP3 Additional Header              :                  Reassembled DNP3 Pseudo Application Layer Data  
//                                                   ||
//                                                   \/
//                                            Binpac DNP3 Analyzer

int DNP3_Analyzer::DNP3_ProcessData(int len, const u_char* data)
	{
	// DNP3 Packet :  DNP3 Pseudo Link Layer | DNP3 Pseudo Transport Layer : DNP3 Pseudo Application Layer

	u_char pseudoLink[PSEUDO_LINK_LEN_EX] ;
	int i;
	int j;
	int newFrame = 0;

	///// the first two bytes should always be 0x0564	
	///// This is used as DPD signature
	if( data[0] != 0x05 || data[1] != 0x64 )
		return -1;

	u_char control_field = data[CRTL_FIELD_INDEX];
	// Double check the orig. in case that the first received traffic is response
	// Such as unsolicited response, a response issued to the control center without receiving any requests
	// I input m_orig into binpac to indicate the flow direction
	bool m_orig = ( (data[CRTL_FIELD_INDEX] & 0x80) == 0x80 );	



	//// The original LEN field on Pseudo Link Layer has only 1 byte;
	//// I increase this field into two bytes to help me buffer more coming application layer data
	j = 0;
	for(i = 0; i < PSEUDO_LINK_LEN ; i++)
		{
		pseudoLink[j] = data[i];
		if(j == LEN_FIELD_INDEX) j++;
	
		j++;
		}

	
	//// ** Perform some checkings on DNP3 Pseudo Transport Layer Data **////
	//// These restrictions can be found in "DNP3 Specification Volume 3, Transport Function"
	
	//// DNP3 Packet :  DNP3 Pseudo Link Layer | DNP3 Pseudo Transport Layer | DNP3 Pseudo Application Layer
	//// DNP3 Serial Transport Layer data is always 1 byte. 
	//// Get FIN FIR seq field in transport header
	//// FIR indicate whether the following DNP3 Serial Application Layer is first trunk of bytes or not 
	//// FIN indicate whether the following DNP3 Serial Application Layer is last trunk of bytes or not 


	//// Get FIR and FIN field from the DNP3 Pseudo Transport Layer
	int aTranFir = (data[PSEUDO_TRAN_INDEX] & 0x40) >> 6; 
	int aTranFin = (data[PSEUDO_TRAN_INDEX] & 0x80) >> 7;
	int aTranSeq = (data[PSEUDO_TRAN_INDEX] & 0x3F);

	//// Four cases based on Combination of FIR and FIN field value
	//// FIR : 1 ; FIN : 1; The carried DNP3 Pseudo Application Layer Data is the 
	////                    complete DNP3 Application Layer Fragment
   	//// FIR : 1 ; FIN : 0; The carried DNP3 Pseudo Application Layer Data is the first trunk  
	////                    of the DNP3 Application Layer Fragment
   	//// FIR : 0 ; FIN : 0; The carried DNP3 Pseudo Application Layer Data is one of intermediate trunk
	////                    of the DNP3 Application Layer Fragment
   	//// FIR : 0 ; FIN : 1; The carried DNP3 Pseudo Application Layer Data is the last trunk of
	////                    the DNP3 Application Layer Fragment
	
	// if FIR field is 1 and FIN field is 0, 
        // the carried DNP3 Pseudo Application Layer Data is the first trunk but not the last trunk, 
	// more trunks will be received afterforwards
	if ( (aTranFir == 1) && (aTranFin == 0) )
		{
		mEncounteredFirst = true;

		//// In this case
		// LEN field value should be 0x00FF
		// The whole length of the DNP3 Packet including all three pseudo layers are MAX_PACKET_SIZE_CRC
		if( len != MAX_PACKET_SIZE_CRC )
			{
			Weird("dnp3_unexpected_packet_size");
			return -4;
			}
		
		//// Here is the trick of exploiting flow_buffer class in binpac
		//// I manually increase the LEN field as 0x0100 
		//// Based on this field, Binpac will allocate the size of flow buffer 
		////  1 byte larger than what is delivered from interp->NewData
		//// As a result, Binpac will buffer the current data and wait for more data to come 
		pseudoLink[LEN_FIELD_INDEX + 1] = 0x01;
                pseudoLink[LEN_FIELD_INDEX] = 0x00;	
		
		//// Send the pseudoLink layer data to binpac
		interp->NewData(m_orig, pseudoLink, pseudoLink + PSEUDO_LINK_LEN_EX);

		///// In order to manipulate flow_buffer class, we need to get its pointer here
		////  Note that we can only call interp->upflow() after interp->NewData, otherwise
		////  Null pointer is returned. 
		////  upflow and downflow is used to calculate the number of trunk that we encounter 
		////  so far
		if( m_orig == true)
			{
                        upflow_count ++;
                        upflow = interp->upflow();
                	}
                else
			{
                        downflow_count ++;
                        downflow = interp->downflow();
                	}
		}

	// If FIR is 0 and FIN is 0, this is a intermediate trunk

	if ( aTranFir == 0 && aTranFin == 0 )
		{
		//// if we lost the first trunk of data but receive intermediate one
		if ( ! mEncounteredFirst )
			{
			Weird("dnp3_first_pseudo_application_layer_trunk_missing");
			return -5;
			}
		
		if ( len != MAX_PACKET_SIZE_CRC )
			{
			// This is not a last transport segment, so the
			// length of the TCP payload should be exactly MAX_PACKET_SIZE_CRC
			// bytes.
			Weird("dnp3_unexpected_payload_size");
			return -6;
			}
		///// When parsing the first trunk of application layer fragment, I manually make Binpac 
		////   allocate the size of flow buffer 1 byte larger than what is delivered from interp->NewData
		////  We continue this trick. 
		////  I manually set the flow buffer as 1 bytes larger than what binpac will receive from 
		////   Interp->NewData 
		////  Note that increaseBuffer is the wrap-up function that I added into DNP3_Flow in binpac 
		////   to call AddFrame function of FlowBuffer class
		////  Also, we did not deliver pseudo Link layer data to binpac as it is intermediate trunk
		if(m_orig == true)
			{
                        //upflow = interp->upflow();
                        //printf("test buffer size %d\n", upflow->get_bufferBytes());
                        newFrame = MAX_PACKET_SIZE_NOCRC + 1 + upflow_count * (MAX_PACKET_SIZE_NOCRC - PSEUDO_LINK_LEN_EX);
                        //printf("new frame size is %d \n", newFrame);
                        upflow->increaseBuffer( MAX_PACKET_SIZE_NOCRC + 1 + upflow_count * (MAX_PACKET_SIZE_NOCRC - PSEUDO_LINK_LEN_EX) );
                        //printf("after increas it ? test buffer size %d\n", upflow->get_bufferBytes());
                        upflow_count++;
                	}
                else
			{
                        downflow = interp->downflow();
                        //printf("down test buffer size %d\n", downflow->get_bufferBytes());
                        newFrame = MAX_PACKET_SIZE_NOCRC + 1 + downflow_count * (MAX_PACKET_SIZE_NOCRC - PSEUDO_LINK_LEN_EX);
                        //printf("down new frame size is %d \n", newFrame);
                        downflow->increaseBuffer( MAX_PACKET_SIZE_NOCRC + 1 + downflow_count * (MAX_PACKET_SIZE_NOCRC - PSEUDO_LINK_LEN_EX) );
                        //printf("down after increas it ? test buffer size %d\n", downflow->get_bufferBytes());
                        downflow_count++;
                	}
		
		}

	if ( aTranFir == 0 && aTranFin == 1 ) // If this is the last segment.
		{
		mEncounteredFirst = false;
	
		///// When the last trunk of application layer fragment comes, I manually make Binpac 
		////   allocate the size of flow buffer exactly the same as  what is delivered from interp->NewData
		////  So binpac analyzer will begin parsing all buffered data
		////  Also, we did not deliver pseudo Link layer data to binpac as it is the last trunk

		if(m_orig == true)
			{
                       	//printf("test buffer size %d\n", upflow->get_bufferBytes());
	                upflow->increaseBuffer( MAX_PACKET_SIZE_NOCRC + 
					(upflow_count - 1) * (MAX_PACKET_SIZE_NOCRC - PSEUDO_LINK_LEN_EX) + 
						pseudoLink[LEN_FIELD_INDEX] -5 - 1 );
        	        upflow_count = 0;
                	}
	        else
			{
        	        //printf("down test buffer size %d\n", downflow->get_bufferBytes());
                        downflow->increaseBuffer( MAX_PACKET_SIZE_NOCRC + 
					(downflow_count - 1) * (MAX_PACKET_SIZE_NOCRC - PSEUDO_LINK_LEN_EX) + 
						pseudoLink[LEN_FIELD_INDEX] - 5 - 1 );
                      	downflow_count = 0;
               		}
			
		}


	// if FIR field is 1 and FIN field is 1, the carried DNP3 Pseudo Application Layer Data is the whole 
	// logic DNP3 application layer fragment
	if ( (aTranFir == 1) && (aTranFin == 1) )
		{
	
		if( mEncounteredFirst == true )
			{
			/// Before this packet, a first transport segment is found
			/// but the finish one is missing
			//// so we should clear out the memory used before; abondon the former 
			//     truncated network packets
			if(m_orig == true)
                        	{
                        	//printf("test buffer size %d\n", upflow->get_bufferBytes());
	                        upflow->discardBuffer();
        	                upflow_count = 0;
                	        }
                	else
                        	{
	                        //printf("down test buffer size %d\n", downflow->get_bufferBytes());
        	                downflow->discardBuffer();
                	        downflow_count = 0;
                        	}
	
			Weird("dnp3_missing_finish_packet");
			mEncounteredFirst = false;
			}
		//// LEN_FIELD_INDEX + 1 incidate the MSB of the length field, should be 0 in this case
		pseudoLink[LEN_FIELD_INDEX + 1]= 0x00;
	

		interp->NewData(m_orig, pseudoLink, pseudoLink + PSEUDO_LINK_LEN_EX);

	
		}
	//// ** End: Perform some checkings on DNP3 Serical Transport Layer Data **////


	//// send data in Pseudo Application Layer to binpac
	int byteRemain = 0;
	int blockLen = 0;
	const u_char* blockStart = NULL;

	
	//printf("App sent to Binpac %d \n", len);

	//// Pseudo Link Layer is already sent; so remove the Pseudo Link
	//// In a single DNP3 Pseudo Application Layer Data trunk, data is divided into 
	//// smaller data block of 18 bytes, in which 16 bytes are data and 2 bytes are CRC
	//// It may look like:
	//// Data Block #1 (16 bytes) CRC (2 bytes)  
	//// Data Block #2 (16 bytes) CRC (2 bytes)  
	//// ...
	//// Last  Data Block  (1 ~ 16 bytes) CRC (2 bytes)
	//// Also note that the first byte in first data block is the Pseudo Transport Layer Data, which
	////  should not be sent to binpac analyzer

	for(i = 0 ; i < ( len - (PSEUDO_LINK_LEN + CRC_LEN) ) ; )
		{
		//// number of bytes remained unsent
		byteRemain = len - (PSEUDO_LINK_LEN + CRC_LEN) - i ;
		//// starting pointer of the current data block
		blockStart = data + (PSEUDO_LINK_LEN + CRC_LEN) + i ;	
	
		if( byteRemain < (DNP3_APP_DATA_BLK + CRC_LEN) )
			{
			blockLen = byteRemain - CRC_LEN;
			
			if( i == 0) // this if statement is used to remove the Pseudo Transport Layer
				{
				blockLen = blockLen - PSEUDO_TRAN_LEN;
				blockStart = blockStart + PSEUDO_TRAN_LEN;
				}
			
			i = i + byteRemain ; 
			}
		else		
			{
			blockLen = DNP3_APP_DATA_BLK;
			
			if( i == 0) // this if statement is used to remove the Pseudo Transport Layer
				{
				blockLen = blockLen - PSEUDO_TRAN_LEN;
				blockStart = blockStart + PSEUDO_TRAN_LEN;
				}
			
			i = i + DNP3_APP_DATA_BLK + CRC_LEN;
			}

		
		/*
                for(j =  0 ; j < trunkLen ; j ++)
                {
                        printf("Ox%x ", blockStart[j]);
                }
                printf("\n");	
		*/
		//// then we deliver data block one by one
		interp->NewData(m_orig, blockStart, blockStart + blockLen);
		}
	//printf("\n\n");

	return 0;	
	}

// DNP3_CheckCRC check the CRC values in the original DNP3 packets
// 

int DNP3_Analyzer::DNP3_CheckCRC(int len, const u_char* data)
	{
	int i = 0;
	int j = 0;
	u_char buffer[18];
	unsigned int crc_result; 
	u_char cal_crc[2]; //crc results calculated
	int last_length = 0; // the length of last user data block

	if(len < 10)
		{
		Weird("DNP3 packets original lenght is less than 10 bytes");
		return -1;
		}	

	// DNP3 Packet :  DNP3 Pseudo Link Layer : DNP3 Pseudo Transport Layer : DNP3 Pseudo Application Layer
	// THe structure of the DNP3 Packet is (can be found in page 8 of DNP3 Specification Volum 4, Data Link Layer)
	// 0x05 0x64 Len Ctrl Dest_LSB Dest_MSB Src_LSB Src_MSB CRC_LSB CRC_MSB (each field is a byte) 
	// Data Block 1 (16 bytes) CRC (2 bytes)
	// Data Block 2 (16 bytes) CRC (2 bytes)
	// .....
	// Last  Data Block  (1 ~ 16 bytes) CRC (2 bytes)
	
	//// first 8 bytes are calcuated for a CRC
	for(i = 0; i < 8; i++)
		{
		buffer[i] = data[i];
		
		}
	
	crc_result = DNP3_CalcCRC(buffer, 8, DNP3_CrcTable, 0x0000, true);
	cal_crc[0] = crc_result & 0xff;
	cal_crc[1] = (crc_result & 0xff00) >> 8;
	if( cal_crc[0] != data[8] || cal_crc[1] != data[9] )
		{
		printf("header: calculated crc: %x %x ; crc: %x %x\n", cal_crc[0], cal_crc[1], data[8], data[9]);
		Weird("Invalid CRC Values");
		return -2;
		}

	//// bytes following the first 10 bytes and before the last user data block
	//// are grouped with size of 18 byte (last 2 bytes are CRC) We check group by group
	//// calculate the legnth of the last user data block (the length of the last user data block
	//// can be any values from 3 bytes to 18 bytes. )
	//// The length of last user data block (last_length) can never be 1 or 2, because
        //// the a user data block can not contain 2-byte CRC bytes without containing any data 

	last_length = ( len - 10) % 18;
	if ( (last_length > 0) && (last_length <= 2) ) 
		{
		Weird("Truncated DNP3 Packets");
		return -3;
		}

	//// check CRC values for user data block by group by group
	for( i = 0; i < (len - 10 - last_length); i++ )
		{
		buffer[i % 18] = data[i + 10];
		if(  i % 18 == 17    )    //// this means that we reach the last element of the user data block, this is the MSB of the CRC
			{	
			crc_result = DNP3_CalcCRC(buffer, 16, DNP3_CrcTable, 0x0000, true);
			cal_crc[0] = crc_result & 0xff;
			cal_crc[1] = (crc_result & 0xff00) >> 8;
			if( cal_crc[0] != buffer[16] || cal_crc[1] != buffer[17] )
				{
				printf("calculated crc: %x %x ; crc: %x %x\n", cal_crc[0], cal_crc[1], buffer[16], buffer[17]);
				Weird("Invalid CRC Values");
				return -2;
				}	
			}
		}

	//// validate crc values for the last data block
	for( i = 0; i < last_length ; i++ )
		{
		//// starting position of the last data block is (len- last_length)
		buffer[i % 18] = data[ i + ( len - last_length ) ];
		if(  i % 18 == ( last_length - 1 )   )
			{	
			crc_result = DNP3_CalcCRC(buffer, ( last_length - 2 ), DNP3_CrcTable, 0x0000, true);
			cal_crc[0] = crc_result & 0xff;
			cal_crc[1] = (crc_result & 0xff00) >> 8;
			if( cal_crc[0] != buffer[last_length - 2] || cal_crc[1] != buffer[last_length - 1] )
				{
				printf("last calculated crc: %x %x ; crc: %x %x\n", cal_crc[0], cal_crc[1], buffer[last_length -2 ], buffer[last_length -1 ]);
				Weird("Invalid CRC Values in last data block");
				return -2;
				}	
			}
		}


	return 0;
	}
//// NOTE I copy codes for the codes for DNP3_CalcCRC and DNP3_PrecomputeCRC from the internet as this is common method to calculate CRC values; is it all right?
void DNP3_Analyzer::DNP3_PrecomputeCRC(unsigned int* apTable, unsigned int aPolynomial)
	{
	unsigned int i, j, CRC;

        for(i = 0; i < 256; i++) 
		{
                CRC = i;
                for (j = 0; j < 8; ++j) 
			{
                        if(CRC & 0x0001) 
				CRC = (CRC >> 1) ^ aPolynomial;
                        else 
				CRC >>= 1;
                	}
                apTable[i] = CRC;
        	}

	}

unsigned int DNP3_Analyzer::DNP3_CalcCRC(u_char* aInput, size_t aLength, const unsigned int* apTable, unsigned int aStart, bool aInvert)
	{
	unsigned int CRC, index;

        CRC = aStart;

        for(size_t i = 0; i < aLength; i++) {
                index = (CRC ^ aInput[i]) & 0xFF;
                CRC = apTable[index] ^ (CRC >> 8);
        }

        if(aInvert) CRC = (~CRC) & 0xFFFF;

        return CRC;
	}



// DNP3_Reassembler();
//
// Purpose: Construct "Hooked DNP3 Serial Application Layer Data" from 
// 	DNP3 Packet :  DNP3 Serial Link Layer : DNP3 Serial Transport Layer : DNP3 Serial Application Layer
// as shown in the above figure
// Inputs: len, serial_data, orig is exactaly passed from DNP3_Analyzer::DeliverStream
// Outputs: app_data: the result "Hooked DNP3 Serial Application Layer Data"  
// Return values: 0 - means no errors
//


