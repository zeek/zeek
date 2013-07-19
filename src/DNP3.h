
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
	static const int MAX_BUFFER_SIZE = 300;

	struct Endpoint
		{
		u_char buffer[MAX_BUFFER_SIZE];
		int buffer_len;
		bool in_hdr;
		int tpflags;
		int pkt_length;
		int pkt_cnt;
		bool encountered_first_chunk;
		};

	bool ProcessData(int len, const u_char* data, bool orig);
	void ClearEndpointState(bool orig);
	bool AddToBuffer(Endpoint* endp, int target_len, const u_char** data, int* len);
	bool ParseAppLayer(Endpoint* endp);
	bool CheckCRC(int len, const u_char* data, const u_char* crc16, const char* where);
	unsigned int CalcCRC(int len, const u_char* data);

	binpac::DNP3::DNP3_Conn* interp;

	Endpoint orig_state;
	Endpoint resp_state;

	static void PrecomputeCRCTable();

	static bool crc_table_initialized;
	static unsigned int crc_table[256];
};

#endif
