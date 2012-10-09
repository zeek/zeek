
#ifndef DNP3_H
#define DNP3_H

#include "TCP.h"
#include "dnp3_pac.h"

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
	int DNP3_Reassembler(int len, const u_char* data, bool orig);
	struct StrByteStream {
		StrByteStream()
			{
			mData = 0;
			length = 0;
			}

		~StrByteStream()
			{
			delete [] mData;
			}

		// Allocate space for given number of bytes.
		void Reserve(int len)
			{
			mData = new u_char[len];
			length = len;
			}

		void Clear()
			{
			delete [] mData;
			mData = 0;
			length = 0;
			}

		u_char* mData;
		int length;
	};

	binpac::DNP3::DNP3_Conn* interp;
	bool mEncounteredFirst;
	StrByteStream gDNP3Data;
};

#endif
