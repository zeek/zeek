
#ifndef DNP3_H
#define DNP3_H

#include "TCP.h"
#include "dnp3_pac.h"

//#define CRC_GEN_POLY 0xA6BC        // Generation Polynomial to calculate 16-bit CRC

#define PSEUDO_LINK_LEN_EX 9       // the length of DNP3 Pseudo Link Layer that extend len field into 2 bytes
#define PSEUDO_TRAN_LEN 1      // the length of DNP3 Pseudo Transport Layer

class DNP3_Analyzer : public TCP_ApplicationAnalyzer {
public:
	DNP3_Analyzer(Connection* conn);
	virtual ~DNP3_Analyzer();

	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(int seq, int len, bool orig);
	virtual void EndpointEOF(TCP_Reassembler* endp);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new DNP3_Analyzer(conn); }

	// Put event names in this function
	static bool Available()
		{ return dnp3_header_block ||
				dnp3_application_request_header || dnp3_object_header ||
				dnp3_response_data_object ||
				dnp3_attribute_common ||
				dnp3_crob || dnp3_pcb ||
				dnp3_counter_32wFlag || dnp3_counter_16wFlag ||
				dnp3_counter_32woFlag || dnp3_counter_16woFlag ||
				dnp3_frozen_counter_32wFlag || dnp3_frozen_counter_16wFlag ||
				dnp3_frozen_counter_32wFlagTime || dnp3_frozen_counter_16wFlagTime ||
				dnp3_frozen_counter_32woFlag || dnp3_frozen_counter_16woFlag ||
				dnp3_analog_input_32wFlag || dnp3_analog_input_16wFlag ||
				dnp3_analog_input_32woFlag || dnp3_analog_input_16woFlag ||
				dnp3_analog_input_SPwFlag || dnp3_analog_input_DPwFlag ||
				dnp3_analog_input_event_32woTime || dnp3_analog_input_event_16woTime ||
				dnp3_analog_input_event_32wTime  || dnp3_analog_input_event_16wTime  ||
				dnp3_analog_input_event_SPwoTime || dnp3_analog_input_event_DPwoTime ||
				dnp3_analog_input_event_SPwTime  || dnp3_analog_input_event_DPwTime  ||
				dnp3_frozen_analog_input_event_32woTime || dnp3_frozen_analog_input_event_16woTime ||
				dnp3_frozen_analog_input_event_32wTime  || dnp3_frozen_analog_input_event_16wTime  ||
				dnp3_frozen_analog_input_event_SPwoTime || dnp3_frozen_analog_input_event_DPwoTime ||
				dnp3_frozen_analog_input_event_SPwTime  || dnp3_frozen_analog_input_event_DPwTime  ||
				dnp3_debug_byte ; }

protected:
	int DNP3_ProcessData(int len, const u_char* data, bool orig);
	int DNP3_CheckCRC(int len, const u_char* data);
	unsigned int DNP3_CalcCRC(u_char* aInput, size_t aLength, const unsigned int* apTable, unsigned int aStart, bool aInvert);	
	void DNP3_PrecomputeCRC(unsigned int* apTable, unsigned int aPolynomial);
	/*
	inline void DNP3_PrecomputeCRC()
		{
		unsigned int i, j, CRC;

        	for(i = 0; i < 256; i++) 
                	{
	                CRC = i;
        	        for (j = 0; j < 8; ++j) 
                	        {
                        	if(CRC & 0x0001) 
                                	CRC = (CRC >> 1) ^ CRC_GEN_POLY;
	                        else 
        	                        CRC >>= 1;
                	        }
	                //apTable[i] = CRC;
	                DNP3_CrcTable[i] = CRC;
        	        }
		}
	*/
	binpac::DNP3::DNP3_Conn* interp;
	binpac::DNP3::DNP3_Flow* upflow;
	binpac::DNP3::DNP3_Flow* downflow;

	unsigned int upflow_count;
	unsigned int downflow_count;
	bool mEncounteredFirst;

//// for the use of calculating CRC values
	unsigned int DNP3_CrcTable[256];
	//// This pseudoLink stores the PseudoLink Layer data which is usually 8 bytes (plus 2 more CRC)
	//// It is possible that TCP carry part of this PseudoLInk Layer, we use this member to buffer 
	////  the incompleted data
	//u_char pseudoLink[PSEUDO_LINK_LEN_EX];
	u_char pseudoLinkResp[PSEUDO_LINK_LEN_EX + PSEUDO_TRAN_LEN];
	unsigned int pseudoLinkRespInd;
	u_char pseudoLinkOrig[PSEUDO_LINK_LEN_EX + PSEUDO_TRAN_LEN];
	unsigned int pseudoLinkOrigInd;
	
};

#endif
