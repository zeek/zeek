// See the file "COPYING" in the main distribution directory for copyright.
//
// Written by Bernhard Ager, TU Berlin (2006/2007).

#ifndef flowsrc_h
#define flowsrc_h

#include "IOSource.h"
#include "NetVar.h"
#include "binpac.h"

#define BRO_FLOW_ERRBUF_SIZE 512

// TODO: 1500 is enough for v5 - how about the others?
// 65536 would be enough for any UDP packet.
#define NF_MAX_PKT_SIZE 8192

struct FlowFileSrcPDUHeader {
	double network_time;
	int pdu_length;
	uint32 ipaddr;
};

// Avoid including netflow_pac.h by explicitly declaring the NetFlow_Analyzer.
namespace binpac {
	namespace NetFlow {
		class NetFlow_Analyzer;
	}
}

class FlowSrc : public IOSource {
public:
	virtual ~FlowSrc();

	// IOSource interface:
	bool IsReady();
	void GetFds(int* read, int* write, int* except);
	double NextTimestamp(double* network_time);
	void Process();

	const char* Tag()		{ return "FlowSrc"; }
	const char* ErrorMsg() const	{ return errbuf; }

protected:
	FlowSrc();

	virtual int ExtractNextPDU() = 0;
	virtual void Close();

	int selectable_fd;

	double current_timestamp;
	double next_timestamp;
	binpac::NetFlow::NetFlow_Analyzer* netflow_analyzer;

	u_char buffer[NF_MAX_PKT_SIZE];
	u_char* data;
	int pdu_len;
	uint32 exporter_ip;	// in network byte order

	char errbuf[BRO_FLOW_ERRBUF_SIZE];
};

class FlowSocketSrc : public FlowSrc {
public:
	FlowSocketSrc(const char* listen_parms);
	virtual ~FlowSocketSrc();

	int ExtractNextPDU();
};

class FlowFileSrc : public FlowSrc {
public:
	FlowFileSrc(const char* readfile);
	~FlowFileSrc();

	int ExtractNextPDU();

protected:
	int Error(int errlvl, const char* errmsg);
	char* readfile;
};

#endif
