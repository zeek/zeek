// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_BACKDOOR_BACKDOOR_H
#define ANALYZER_PROTOCOL_BACKDOOR_BACKDOOR_H

#include "analyzer/protocol/tcp/TCP.h"
#include "Timer.h"
#include "NetVar.h"
#include "analyzer/protocol/login/Login.h"

namespace analyzer { namespace backdoor {

class BackDoorEndpoint {
public:
	BackDoorEndpoint(tcp::TCP_Endpoint* e);

	int DataSent(double t, uint64 seq, int len, int caplen, const u_char* data,
		     const IP_Hdr* ip, const struct tcphdr* tp);

	RecordVal* BuildStats();

	void FinalCheckForRlogin();

protected:
	void CheckForRlogin(uint64 seq, int len, const u_char* data);
	void RloginSignatureFound(int len);

	void CheckForTelnet(uint64 seq, int len, const u_char* data);
	void TelnetSignatureFound(int len);

	void CheckForSSH(uint64 seq, int len, const u_char* data);
	void CheckForFTP(uint64 seq, int len, const u_char* data);
	void CheckForRootBackdoor(uint64 seq, int len, const u_char* data);
	void CheckForNapster(uint64 seq, int len, const u_char* data);
	void CheckForGnutella(uint64 seq, int len, const u_char* data);
	void CheckForKazaa(uint64 seq, int len, const u_char* data);
	void CheckForHTTP(uint64 seq, int len, const u_char* data);
	void CheckForHTTPProxy(uint64 seq, int len, const u_char* data);
	void CheckForSMTP(uint64 seq, int len, const u_char* data);
	void CheckForIRC(uint64 seq, int len, const u_char* data);
	void CheckForGaoBot(uint64 seq, int len, const u_char* data);

	void SignatureFound(EventHandlerPtr e, int do_orig = 0);

	int CheckForStrings(const char** strs, const u_char* data, int len);
	int CheckForFullString(const char* str, const u_char* data, int len);
	int CheckForString(const char* str, const u_char* data, int len);

	tcp::TCP_Endpoint* endp;
	int is_partial;
	uint64 max_top_seq;

	int rlogin_checking_done;
	int rlogin_num_null;
	uint64 rlogin_string_separator_pos;
	int rlogin_slash_seen;

	uint32 num_pkts;
	uint32 num_8k4_pkts;
	uint32 num_8k0_pkts;
	uint32 num_lines;
	uint32 num_normal_lines;
	uint32 num_bytes;
	uint32 num_7bit_ascii;
};

class BackDoor_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	BackDoor_Analyzer(Connection* c);
	~BackDoor_Analyzer();

	virtual void Init();
	virtual void Done();
	void StatTimer(double t, int is_expire);

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new BackDoor_Analyzer(conn); }

protected:
	// We support both packet and stream input, and can be instantiated
	// even if the TCP analyzer is not yet reassembling.
	virtual void DeliverPacket(int len, const u_char* data, bool is_orig,
					uint64 seq, const IP_Hdr* ip, int caplen);
	virtual void DeliverStream(int len, const u_char* data, bool is_orig);

	void StatEvent();
	void RemoveEvent();

	BackDoorEndpoint* orig_endp;
	BackDoorEndpoint* resp_endp;

	int orig_stream_pos;
	int resp_stream_pos;

	double timeout;
	double backoff;
};

class BackDoorTimer : public Timer {
public:
	BackDoorTimer(double t, BackDoor_Analyzer* a);
	~BackDoorTimer();

	void Dispatch(double t, int is_expire);

protected:
	BackDoor_Analyzer* analyzer;
};

} } // namespace analyzer::* 

#endif
