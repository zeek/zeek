// $Id:$
//
// This template code contributed by Kristin Stephens.

#ifndef dnp3_h
#define dnp3_h

#include "TCP.h"
//#include "DNP3-TCP.h"
#include "dnp3_pac.h"

class DNP3_Analyzer : public TCP_ApplicationAnalyzer {
//class DNP3_Analyzer : public DNP3TCP_Analyzer {
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
		{ return dnp3_header_block || dnp3_data_block || dnp3_pdu_test || 
				dnp3_application_request_header || dnp3_object_header || 
				dnp3_response_data_object ||
				dnp3_crob || dnp3_pcb ||
				dnp3_counter32_wFlag || dnp3_counter16_wFlag || 
				dnp3_counter32_woFlag || dnp3_counter16_woFlag ||
				dnp3_frozen_counter32_wFlag || dnp3_frozen_counter16_wFlag ||
				dnp3_frozen_counter32_wFlagTime || dnp3_frozen_counter16_wFlagTime ||
				dnp3_frozen_counter32_woFlag || dnp3_frozen_counter16_woFlag ||
				dnp3_analog_input32_wFlag || dnp3_analog_input16_wFlag ||
				dnp3_analog_input32_woFlag || dnp3_analog_input16_woFlag ||
				dnp3_analog_inputSP_wFlag || dnp3_analog_inputDP_wFlag ||
				dnp3_analog_input32_woTime || dnp3_analog_input16_woTime || 
				dnp3_analog_input32_wTime  || dnp3_analog_input16_wTime  ||
				dnp3_analog_inputSP_woTime || dnp3_analog_inputDP_woTime ||
				dnp3_analog_inputSP_wTime  || dnp3_analog_inputDP_wTime  ||
				dnp3_debug_byte; }

protected:
	binpac::Dnp3::Dnp3_Conn* interp;
};

#endif
