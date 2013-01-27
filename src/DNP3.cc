
#include "DNP3.h"
#include "TCP_Reassembler.h"


#define USE_BUFFER 

DNP3_Analyzer::DNP3_Analyzer(Connection* c) : TCP_ApplicationAnalyzer(AnalyzerTag::DNP3, c)
	{
	mEncounteredFirst = false;

	//// precompute CrcTable from this magic number
	this->DNP3_PrecomputeCRC(DNP3_CrcTable, 0xA6BC);  
	
	interp = new binpac::DNP3::DNP3_Conn(this);
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
// DNP3 Packet ->  DNP3 Pseudo Link Layer : DNP3 Pseudo Transport Layer : DNP3 Pseudo Application Layer
// (this hierarchy can be vied in the Wireshark visually)
//
// When DeliverStream is called, "data" contains DNP3 packets consisting of all pseudo three layers. 
// I use the binpac to write the parser of DNP3 Pseudo Application Layer only instead of the whole application 
// layer payload. The following list explains why I am doing this and other challenges with my resolutions:
//
// 1. Basic structure of DNP3 Protocol over serial links. This information can be found in detail in 
//     DNP3 Specification Volum 2, Part 1 Basic, Application Layer
//     DNP3 Specification Volum 4, Data Link Layer
// In history, the DNP3 Application Layer in serial links contains "DNP3 Application Layer Fragment", the data that is 
// parsed by the end device and is executed. The "DNP3 Application Layer Fragment" can carried in 
// DNP3 Pseudo Application Layer of more than one DNP3 packets
// It relies on the DNP3 device to decide what a upper pound of the fragment size is. 
// However, a long (> 255 bytes) DNP3 applicaiton fragment have to be truncated put into 
// Pseudo Application Layer (just mentioned) which is indexed different Data Link Layer headers. 
// So the whole DNP3 fragment transmitted over serial link may look like (since we are talking 
// about serial link communicaiton in this small section, so "Pseudo" is removed in the name)
//
// DNP3 Packet ->  DNP3 Link Layer : DNP3 Transport Layer : DNP3 Application Layer #1
// DNP3 Packet ->  DNP3 Link Layer : DNP3 Transport Layer : DNP3 Application Layer #2
// ....
// DNP3 Packet ->  DNP3 Link Layer : DNP3 Transport Layer : DNP3 Application Layer #n
// 
// So to get the whole DNP3 application Fragment, we concatenate each DNP3 Application Layer Data. 
// A logic DNP3 Fragment = DNP3 Application Layer #1 + DNP3 Application Layer #2 + ... + DNP3 Application Layer #n
//
// Note: The detailed structure of the DNP3 Link Layer is: 
// 0x05 0x64 Len Ctrl Dest_LSB Dest_MSB Src_LSB Src_MSB CRC_LSB CRC_MSB 
//       (each field is a byte; LSB: least significant byte; MSB: Most significatn Byte )
// "Len" field indicates the length of the byte stream right after this field (execluding CRC fields). 
// Since "Len" field is of size one byte, so largest length it can represent is 255 bytes. 
// The larget DNP3 Application Layer size is (255 - 5 + size of all CRC fields). minus 5 is coming from
// the 5 bytes after "Len" field in the DNP3 Link Layer, i.e. Ctrl Dest_LSB Dest_MSB Src_LSB Src_MSB
// Through calculation, the largest size of 
// a DNP3 Packet (DNP3 Data Link Layer : DNP3 Transport Layer : DNP3 Application Layer) can only be 
//  292 bytes. 


// 2. A single logic DNP3 Applicatino Layer Fragment can be truncated into several DNP3 Pseudo Application Layer data included under 
// different DNP3 Pseudo Data Link Layer header. As a result, in some situation, 
// reassembly is needed to construct the DNP3 Application Layer. 
// (This is similar to TCP reassembly, but happened in the application layer of the TCP/IP stack).
// I find it very challenging to do this reassembly in binpac scripts. So the codes before the calling of interp->NewData
// is to actually (1) extract bytes stream of DNP3 Pseudo Application Layer from the whole application layer trunk and 
// then deliver them to the binpac analyzer; (2) perform the aformentioned reassembly if necessary. 
//
// 3. The DNP3 Pseudo Application Layer does not include a length field which indicate the length of this layer.
// This brings challenges to write the binpac scripts. So, I extract the
// length field (LEN field) in the DNP3 Pseudo Data Link Layer and do some computations to get 
// the length of DNP3 Pseudo Application Layer and hook the original DNP3 Pseudo Application Layer data 
// with a additional header (this is represented by the type of Header_Block in the binpac script) 
// In this way, the DNP3 Pseudo Application Layer data can be represented properly by DNP3_Flow in binpac script
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
//TODO-Hui: Information from the DNP3 Pseudo Data Link Layer may generate events as well
// so I exactly copy the information 
//          from Pseudo Data Link Layer into the DNP3 Additional Header (excluding CRC values)
// The structure of the DNP3 Pseudo Link Layer is: 0x05 0x64 Len Ctrl Dest_LSB Dest_MSB Src_LSB Src_MSB CRC_LSB CRC_MSB
// And the DNP3 Additional Header is defined as:
// type Header_Block = record {
//        start: uint16 &check(start == 0x0564);
//        len: uint8;
//        ctrl: uint8;  
//        dest_addr: uint16;
//        src_addr: uint16;
// } &byteorder = littleendian
//   &length = 8;
// By doing this, we can use binpac analyzer to generate events from DNP3 Pseudo Data Link Layer.
// However by doing this, a problem is generated. "LEN" field is 1 byte which can only represent 
// a logic DNP3 fragment with length less than or equal to 255 bytes. 
// My TEMPORARY solution is, if the length of the logic DNP3 fragment is larger than 255 bytes, I use 
// "Ctrl" contains the higher 8-bit values of the length.(then the original information in "Ctrl" is lost)
// That is why in this version of the DNP3 analyzer, we can only handle a logic DNP3 fragment with size of 65535 bytes.
// Later, I will manually increae "len" to be 32 bit.  


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
	// User Data Block 1 (16 bytes) CRC (2 bytes)
	// User Data Block 2 (16 bytes) CRC (2 bytes)
	// .....
	// Last  User Data Block  (1 ~ 16 bytes) CRC (2 bytes)
	
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


// DNP3_CopyDataBlock
// This function did the real job of constructing the logical DNP3 fragment from the original DNP3 packet:
// (1) construct the DNP3 Additional Header for Binpac analyzer
// (2) remove the CRC values from DNP3 Pseudo Application Layer

int DNP3_Analyzer::DNP3_CopyDataBlock(struct StrByteStream* target, const u_char* data, int len)
	{
	int dnp3_i = 0; // Index within the data block.

	// target->mData should be allocated memory space; but double check here to avoid misuse
	if(target->mData == NULL)
		{
		Weird("DNP3_CopyDataBlock target buffer is not allocated");
		return -1;
		}
	
	memcpy(target->mData, data, 8); // Keep the first 8 bytes.

	for( int i = 0; i < len - 10; i++ )
		{
                if ( (i % 18 != 16) && (i % 18 != 17) // Does not include crc on each data block (not the last data block)
                        && ((len - 10 - i) > 2)       // Does not include crc on the last data block 
                        && ( i != 0 ) )               // Does not sent first byte which is DNP3 Pseudo Transport Layer data into binpac analyzer
			{
                       	//gDNP3Data.mData[dnp3_i + 8] = data[i + 10];
			target->mData[dnp3_i + 8] = data[i + 10];
                        dnp3_i++;
                        }
                }

        //gDNP3Data.length = dnp3_i + 8;
        target->length = dnp3_i + 8;
	return 0;	
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
int DNP3_Analyzer::DNP3_Reassembler(int len, const u_char* data, bool orig)
	{
	// DNP3 Packet :  DNP3 Serial Link Layer : DNP3 Serial Transport Layer : DNP3 Serial Application Layer
	
	//// ** Perform some checkings on DNP3 Serial Link Layer Data **////
	//// These restrictions can be found in "DNP3 Specification Volume 4, Data Link Layer"

	// The first two bytes of DNP3 Serial Link Layer data is always 0564....
	// If it is not serial protocol data ignore.
	if( data[0] != 0x05 || data[1] != 0x64 )
		return -1;

	// Double check the orig. in case that the first received traffic is response
	// Such as unsolicited response, a response issued to the control center without receiving any requests
	u_char control_field = data[3];
	
	// DNP3 Serial Link Layer Data can actually be used without being followed any DNP3 Serial Transport Layer and 
	// DNP3 Serial Application Layer data. It is the legacy design of serial link communication and may be used to detect
	// network status. A function code field (this is different from the function field you will find in 
	// DNP3 Serial Application Layer), indicate link layer functionality. 
	//// In this version of DNP3 Analyer, events from DNP3 Serial Link Layer data is not supported. 
	///// The 4-bit function code field, included in 4-bit control_field byte, is 0x03, then DNP3 Serial Transport Layer data and 
	//     DNP3 Serial Application Layer data is deliverd with confirmation requested .
 	///// The 4-bit function code field, included in 4-bit control_field byte, is 0x04, then DNP3 Serial Transport Layer data and 
	//     DNP3 Serial Application Layer data is deliverd without confirmation requested . 

	// TODO-Hui PRM bit
	if ( (control_field & 0x0F) != 0x03 && (control_field & 0x0F) != 0x04 )
		return -2;

	//// ** End: Perform some checkings on DNP3 Serial Link Layer Data **////
	
	//// ** Perform some checkings on DNP3 Serical Transport Layer Data **////
	//// These restrictions can be found in "DNP3 Specification Volume 3, Transport Function"
	
	//// DNP3 Packet :  DNP3 Serial Link Layer : DNP3 Serial Transport Layer : DNP3 Serial Application Layer
	//// DNP3 Serial Transport Layer data is always 1 byte. 
	//// Get FIN FIR seq field in transport header
	//// FIR indicate whether the following DNP3 Serial Application Layer is first trunk of bytes or not 
	//// FIN indicate whether the following DNP3 Serial Application Layer is last trunk of bytes or not 
	int aTranFir = (data[10] & 0x40) >> 6;
	int aTranFin = (data[10] & 0x80) >> 7;
	int aTranSeq = (data[10] & 0x3F);

	
	// if FIR field is 1 and FIN field is 0, the carried DNP3 Pseudo Application Layer Data is the first trunk but not the last trunk, 
	// more trunks will be received afterforwards
	if ( (aTranFir == 1) && (aTranFin == 0) )
		{
		mEncounteredFirst = true;

		if( len != 292 )
			{
			// The largest length of the DNP3 Pseudo Application Layer Data is 292 bytes including the crc values 
			// If the DNP3 packet contains the first DNP3 Pseudo Application Layer Data but not the last
			// its size should be exactly 292 bytes. But vise versa is not true.
			Weird("dnp3_unexpected_payload_size");
			return -4;
			}
		gDNP3Data.Reserve(len);

		//memcpy(gDNP3Data.mData, data, 8); // Keep the first 8 bytes.

		// As mentioned what data includes is :
		// DNP3 Packet :  DNP3 Pseudo Link Layer : DNP3 Pseudo Transport Layer : DNP3 Pseudo Application Layer
		// In details. THe structure of the DNP3 Packet is (can be found in page 8 of DNP3 Specification Volum 4, Data Link Layer)
		// The structure of DNP3 Pseudo Link Layer Data is
		// 0x05 0x64 Len Ctrl Dest_LSB Dest_MSB Src_LSB Src_MSB CRC_LSB CRC_MSB (each field is a byte)
		// The structure of DNP3 Pseudo Transport Layer (1 Byte) and DNP3 Pseudo APplication Layer is 
		// User Data Block 1 (16 bytes) CRC (2 bytes)
		// User Data Block 2 (16 bytes) CRC (2 bytes)
		// .....
		// Last  User Data Block  (1 ~ 16 bytes) CRC (2 bytes)
		// DNP3 fragment

		DNP3_CopyDataBlock(&gDNP3Data, data, len);	
		/*	
		int dnp3_i = 0; // Index within the data block.

		for( int i = 0; i < len - 10; i++ )
			{
			if ( (i % 18 != 16) && (i % 18 != 17) // Does not include crc on each data block (not the last data block)
				&& ((len - 10 - i) > 2)       // Does not include crc on the last data block 
				&& ( i != 0 ) )               // Does not sent first byte which is DNP3 Pseudo Transport Layer data into binpac analyzer
				{
				gDNP3Data.mData[dnp3_i + 8] = data[i + 10];
				dnp3_i++;
				}
			}

		gDNP3Data.length = dnp3_i + 8;
		*/
		return 1;  
		}

	// If FIR is 0, the carried DNP3 Pseudo Application Layer Data is not the first trunk. So this trunk can be either middle trunk
	// or the last trunk (FIN field is 1)

	if ( aTranFir == 0 )
		{
		if ( ! mEncounteredFirst )
			{
			Weird("dnp3_first_transport_sgement_missing");
			return -5;
			}
	
		if ( (aTranFin == 0) && (len != 292) )
			{
			// This is not a last transport segment, so the
			// length of the TCP payload should be exactly 292
			// bytes.
			Weird("unexpected_payload_length");
			return -6;
			}
	
		//// Since this DNP3 Pseudo Application Layer Data is either a middle trunk of the last trunk,
		//// we have to concate bytes in "data" into the previous data trunk in order to form the complete 
		//// logicl DNP3 Application layer fragment

		//// a temporary buffer is used to store the bytes issued in previous data trunk
		int aTempFormerLen = gDNP3Data.length;
		u_char* aTempResult = new u_char[len + aTempFormerLen];
		memcpy(aTempResult, gDNP3Data.mData, aTempFormerLen);

		//// Add bytes in "data" into previous trunk
		//// This piece of code has some differences from the code included in DNP3_CopyDataBlock,
		//// So I left it as it is. 
		int dnp3_i = 0;

		for( int i = 0; i < (len - 10); i++ )
			{
			if( (i % 18 != 16) && (i % 18 != 17) // Does not include crc on each data block.
				&& ((len - 10 - i) > 2)      // Does not include last data block.
				&& ( i != 0 ) )              // Does not consider first byte, transport layer header.
				{
				// can not over flow; as the size of the temporary buffer is 
				// len + gDNP3Data.length; "len" is the length of data
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
			
			// In my TEMPORARY solution, I use "len" (1 byte) and "ctrl" (1 byte) in DNP3 Additional Header to 
			// represent the length of the whole DNP3 fragment. 
			if( gDNP3Data.length >= 65536 )
				{
				Weird("dnp3_data_exceeds_65K");
				gDNP3Data.Clear();
				return -7;
				}
			// "len" in DNP3 Additional Header contains the lower 8 bit of the length
			gDNP3Data.mData[2] = (gDNP3Data.length - 2) % 0x100;  
			// "ctrl" in DNP3 Additional Header contains the higher 8 bit of the length
			gDNP3Data.mData[3] = ((gDNP3Data.length -2) & 0xFF00) >> 8;

			/// call this function in the this->DeliveryStream
			////interp->NewData(m_orig, gDNP3Data.mData, gDNP3Data.mData + gDNP3Data.length );
			
			// move it to DNP3_Analyzer::DeliverStream
			//gDNP3Data.Clear();
			return 0;
			}

		return 1;
		}

	// if FIR field is 1 and FIN field is 1, the carried DNP3 Pseudo Application Layer Data is the whole 
	// logic DNP3 application layer fragment
	if ( (aTranFir == 1) && (aTranFin == 1) )
		{
		//// can directly use gDNP3Data
		////u_char* tran_data = new u_char[len]; // Definitely not more than original data payload.
		if( mEncounteredFirst == true )
			{
			/// Before this packet, a first transport segment is found
			/// but the finish one is missing
			//// so we should clear out the memory used before; abondon the former 
			//     truncated network packets
			//  But this newly received packets should be delivered to the binpac as usuall
			gDNP3Data.Clear();
			Weird("dnp3_missing_finish_packet");
			}

		gDNP3Data.Reserve(len);
		DNP3_CopyDataBlock(&gDNP3Data, data, len);
		//// since this is the only application layer trunk, so the higer 8bits of the length is 0
		gDNP3Data.mData[3] = 0x00;
		/*
		//memcpy(tran_data, data, 8); // Keep the first 8 bytes.
		
		memcpy(gDNP3Data.mData, data, 8); // Keep the first 8 bytes.

		int dnp3_i = 0;

		for( int i = 0; i < len - 10; i++ )
			{
			if ( (i % 18 != 16) && (i % 18 != 17) // Does not include crc on each data block.
		     		&& ((len - 10 - i) > 2)       // Does not include last data block.
		     		&& ( i != 0 ) )               // Does not consider first byte, transport layer header.
				{
				// TODO-HUi: Insert commenty what this is doing.
				// TODO-Hui: Can this overflow?
				//tran_data[dnp3_i + 8] = data[i + 10];
				gDNP3Data.mData[dnp3_i + 8] = data[i + 10];
				dnp3_i++;
				}
			}
		//tran_data[3] = 0;   // Put ctrl as zero as the high-8bit.
		gDNP3Data.mData[3] = 0;   // Put ctrl as zero as the high-8bit.
		//int dnp3_length = dnp3_i + 8;
		gDNP3Data.length = dnp3_i + 8;
		//interp->NewData(m_orig, tran_data, tran_data + dnp3_length);
		*/

		//delete [] tran_data;

		// This is for the abnormal traffic pattern such as a a first
		// application packet is sent but no last segment is found.
		mEncounteredFirst = false;
		//gDNP3Data.Clear();
	
		}
	//// ** End: Perform some checkings on DNP3 Serical Transport Layer Data **////

	return 0;	
	}

void DNP3_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{

	TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	int result = 0;
	
	//// Checkec the CRC values included in the DNP3 packets
	DNP3_CheckCRC(len, data);
	
	if( data[0] != 0x05 || data[1] != 0x64 )
		return ;


	#ifdef USE_BUFFER
	result = DNP3_Reassembler2(len, data, orig);
	gDNP3Data.mData[3] = 0x00;
	
	#else

	/// if result > 0, then DNP3_Reassembler reassembles the intermediate trunk
	//// if result < 0, errors happened in DNP3_Reassembler.
	result = DNP3_Reassembler(len, data, orig);		
	if(result != 0){
		return ;	
	}
	#endif
	
	bool m_orig = ( (data[3] & 0x80) == 0x80 );

	int i = 0;
	printf("\nBytes into BInpac analzyer:");
	for (i = 0; i < gDNP3Data.length ; i++)
		printf("0x%x ", gDNP3Data.mData[i]);
	printf("\n");

		
	interp->NewData(m_orig, gDNP3Data.mData, gDNP3Data.mData + gDNP3Data.length );

	gDNP3Data.Clear();

	#ifdef USE_BUFFER
	if(result == 10){
		//interp->FlowEOF(m_orig);	
		//interp->FlowEOF(true);	
		//interp->FlowEOF(false);	
	}	
	#endif


	
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


int DNP3_Analyzer::DNP3_Reassembler2(int len, const u_char* data, bool orig)
	{
	// DNP3 Packet :  DNP3 Serial Link Layer : DNP3 Serial Transport Layer : DNP3 Serial Application Layer
	
	//// ** Perform some checkings on DNP3 Serial Link Layer Data **////
	//// These restrictions can be found in "DNP3 Specification Volume 4, Data Link Layer"

	// The first two bytes of DNP3 Serial Link Layer data is always 0564....
	// If it is not serial protocol data ignore.
	if( data[0] != 0x05 || data[1] != 0x64 )
		return -1;

	// Double check the orig. in case that the first received traffic is response
	// Such as unsolicited response, a response issued to the control center without receiving any requests
	u_char control_field = data[3];
	
	// DNP3 Serial Link Layer Data can actually be used without being followed any DNP3 Serial Transport Layer and 
	// DNP3 Serial Application Layer data. It is the legacy design of serial link communication and may be used to detect
	// network status. A function code field (this is different from the function field you will find in 
	// DNP3 Serial Application Layer), indicate link layer functionality. 
	//// In this version of DNP3 Analyer, events from DNP3 Serial Link Layer data is not supported. 
	///// The 4-bit function code field, included in 4-bit control_field byte, is 0x03, then DNP3 Serial Transport Layer data and 
	//     DNP3 Serial Application Layer data is deliverd with confirmation requested .
 	///// The 4-bit function code field, included in 4-bit control_field byte, is 0x04, then DNP3 Serial Transport Layer data and 
	//     DNP3 Serial Application Layer data is deliverd without confirmation requested . 

	// TODO-Hui PRM bit
	if ( (control_field & 0x0F) != 0x03 && (control_field & 0x0F) != 0x04 )
		return -2;

	//// ** End: Perform some checkings on DNP3 Serial Link Layer Data **////
	
	//// ** Perform some checkings on DNP3 Serical Transport Layer Data **////
	//// These restrictions can be found in "DNP3 Specification Volume 3, Transport Function"
	
	//// DNP3 Packet :  DNP3 Serial Link Layer : DNP3 Serial Transport Layer : DNP3 Serial Application Layer
	//// DNP3 Serial Transport Layer data is always 1 byte. 
	//// Get FIN FIR seq field in transport header
	//// FIR indicate whether the following DNP3 Serial Application Layer is first trunk of bytes or not 
	//// FIN indicate whether the following DNP3 Serial Application Layer is last trunk of bytes or not 
	int aTranFir = (data[10] & 0x40) >> 6;
	int aTranFin = (data[10] & 0x80) >> 7;
	int aTranSeq = (data[10] & 0x3F);

	
	// if FIR field is 1 and FIN field is 0, the carried DNP3 Pseudo Application Layer Data is the first trunk but not the last trunk, 
	// more trunks will be received afterforwards
	if ( (aTranFir == 1) && (aTranFin == 0) )
		{
		mEncounteredFirst = true;

		if( len != 292 )
			{
			// The largest length of the DNP3 Pseudo Application Layer Data is 292 bytes including the crc values 
			// If the DNP3 packet contains the first DNP3 Pseudo Application Layer Data but not the last
			// its size should be exactly 292 bytes. But vise versa is not true.
			Weird("dnp3_unexpected_payload_size");
			return -4;
			}
		gDNP3Data.Reserve(len);

		//memcpy(gDNP3Data.mData, data, 8); // Keep the first 8 bytes.

		// As mentioned what data includes is :
		// DNP3 Packet :  DNP3 Pseudo Link Layer : DNP3 Pseudo Transport Layer : DNP3 Pseudo Application Layer
		// In details. THe structure of the DNP3 Packet is (can be found in page 8 of DNP3 Specification Volum 4, Data Link Layer)
		// The structure of DNP3 Pseudo Link Layer Data is
		// 0x05 0x64 Len Ctrl Dest_LSB Dest_MSB Src_LSB Src_MSB CRC_LSB CRC_MSB (each field is a byte)
		// The structure of DNP3 Pseudo Transport Layer (1 Byte) and DNP3 Pseudo APplication Layer is 
		// User Data Block 1 (16 bytes) CRC (2 bytes)
		// User Data Block 2 (16 bytes) CRC (2 bytes)
		// .....
		// Last  User Data Block  (1 ~ 16 bytes) CRC (2 bytes)
		// DNP3 fragment

		DNP3_CopyDataBlock(&gDNP3Data, data, len);	
		/*	
		int dnp3_i = 0; // Index within the data block.

		for( int i = 0; i < len - 10; i++ )
			{
			if ( (i % 18 != 16) && (i % 18 != 17) // Does not include crc on each data block (not the last data block)
				&& ((len - 10 - i) > 2)       // Does not include crc on the last data block 
				&& ( i != 0 ) )               // Does not sent first byte which is DNP3 Pseudo Transport Layer data into binpac analyzer
				{
				gDNP3Data.mData[dnp3_i + 8] = data[i + 10];
				dnp3_i++;
				}
			}

		gDNP3Data.length = dnp3_i + 8;
		*/
		return 1;  
		}

	// If FIR is 0, the carried DNP3 Pseudo Application Layer Data is not the first trunk. So this trunk can be either middle trunk
	// or the last trunk (FIN field is 1)

	if ( aTranFir == 0 )
		{
		if ( ! mEncounteredFirst )
			{
			Weird("dnp3_first_transport_sgement_missing");
			return -5;
			}
	
		if ( (aTranFin == 0) && (len != 292) )
			{
			// This is not a last transport segment, so the
			// length of the TCP payload should be exactly 292
			// bytes.
			Weird("unexpected_payload_length");
			return -6;
			}
	
		//// Since this DNP3 Pseudo Application Layer Data is either a middle trunk of the last trunk,
		//// we have to concate bytes in "data" into the previous data trunk in order to form the complete 
		//// logicl DNP3 Application layer fragment

		//// a temporary buffer is used to store the bytes issued in previous data trunk
		//int aTempFormerLen = gDNP3Data.length;
		//u_char* aTempResult = new u_char[len + aTempFormerLen];
		//memcpy(aTempResult, gDNP3Data.mData, aTempFormerLen);

		//// Add bytes in "data" into previous trunk
		//// This piece of code has some differences from the code included in DNP3_CopyDataBlock,
		//// So I left it as it is. 
		int dnp3_i = 0;

		for( int i = 0; i < (len - 10); i++ )
			{
			if( (i % 18 != 16) && (i % 18 != 17) // Does not include crc on each data block.
				&& ((len - 10 - i) > 2)      // Does not include last data block.
				&& ( i != 0 ) )              // Does not consider first byte, transport layer header.
				{
				// can not over flow; as the size of the temporary buffer is 
				// len + gDNP3Data.length; "len" is the length of data
				//aTempResult[dnp3_i + aTempFormerLen] = data[i + 10];
				gDNP3Data.mData[dnp3_i] = data[i + 10];
				dnp3_i++;
				}
			}

		//delete [] gDNP3Data.mData;
		//gDNP3Data.mData = aTempResult;
		//gDNP3Data.length = dnp3_i + aTempFormerLen;
		gDNP3Data.length = dnp3_i;
		
		if ( aTranFin == 1 ) // If this is the last segment.
			{
			mEncounteredFirst = false;
			
			// In my TEMPORARY solution, I use "len" (1 byte) and "ctrl" (1 byte) in DNP3 Additional Header to 
			// represent the length of the whole DNP3 fragment. 
			if( gDNP3Data.length >= 65536 )
				{
				Weird("dnp3_data_exceeds_65K");
				gDNP3Data.Clear();
				return -7;
				}
			// "len" in DNP3 Additional Header contains the lower 8 bit of the length
			//gDNP3Data.mData[2] = (gDNP3Data.length - 2) % 0x100;  
			// "ctrl" in DNP3 Additional Header contains the higher 8 bit of the length
			//gDNP3Data.mData[3] = ((gDNP3Data.length -2) & 0xFF00) >> 8;

			/// call this function in the this->DeliveryStream
			////interp->NewData(m_orig, gDNP3Data.mData, gDNP3Data.mData + gDNP3Data.length );
			
			// move it to DNP3_Analyzer::DeliverStream
			//gDNP3Data.Clear();
			return 10;
			}

		return 1;
		}

	// if FIR field is 1 and FIN field is 1, the carried DNP3 Pseudo Application Layer Data is the whole 
	// logic DNP3 application layer fragment
	if ( (aTranFir == 1) && (aTranFin == 1) )
		{
		//// can directly use gDNP3Data
		////u_char* tran_data = new u_char[len]; // Definitely not more than original data payload.
		if( mEncounteredFirst == true )
			{
			/// Before this packet, a first transport segment is found
			/// but the finish one is missing
			//// so we should clear out the memory used before; abondon the former 
			//     truncated network packets
			//  But this newly received packets should be delivered to the binpac as usuall
			gDNP3Data.Clear();
			Weird("dnp3_missing_finish_packet");
			}

		gDNP3Data.Reserve(len);
		DNP3_CopyDataBlock(&gDNP3Data, data, len);
		//// since this is the only application layer trunk, so the higer 8bits of the length is 0
		gDNP3Data.mData[3] = 0x00;
		/*
		//memcpy(tran_data, data, 8); // Keep the first 8 bytes.
		
		memcpy(gDNP3Data.mData, data, 8); // Keep the first 8 bytes.

		int dnp3_i = 0;

		for( int i = 0; i < len - 10; i++ )
			{
			if ( (i % 18 != 16) && (i % 18 != 17) // Does not include crc on each data block.
		     		&& ((len - 10 - i) > 2)       // Does not include last data block.
		     		&& ( i != 0 ) )               // Does not consider first byte, transport layer header.
				{
				// TODO-HUi: Insert commenty what this is doing.
				// TODO-Hui: Can this overflow?
				//tran_data[dnp3_i + 8] = data[i + 10];
				gDNP3Data.mData[dnp3_i + 8] = data[i + 10];
				dnp3_i++;
				}
			}
		//tran_data[3] = 0;   // Put ctrl as zero as the high-8bit.
		gDNP3Data.mData[3] = 0;   // Put ctrl as zero as the high-8bit.
		//int dnp3_length = dnp3_i + 8;
		gDNP3Data.length = dnp3_i + 8;
		//interp->NewData(m_orig, tran_data, tran_data + dnp3_length);
		*/

		//delete [] tran_data;

		// This is for the abnormal traffic pattern such as a a first
		// application packet is sent but no last segment is found.
		mEncounteredFirst = false;
		//gDNP3Data.Clear();
	
		}
	//// ** End: Perform some checkings on DNP3 Serical Transport Layer Data **////

	return 0;	
	}
