// $Id: ICMP.h 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#ifndef icmp_h
#define icmp_h

#include "Analyzer.h"

typedef enum {
	ICMP_INACTIVE,	// no packet seen
	ICMP_ACTIVE,	// packets seen
} ICMP_EndpointState;

// We do not have an PIA for ICMP (yet) and therefore derive from
// RuleMatcherState to perform our own matching.
class ICMP_Analyzer : public TransportLayerAnalyzer {
public:
	ICMP_Analyzer(Connection* conn);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new ICMP_Analyzer(conn); }

	static bool Available()	{ return true; }

protected:
	ICMP_Analyzer()	{ }
	ICMP_Analyzer(AnalyzerTag::Tag tag, Connection* conn);

	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					int seq, const IP_Hdr* ip, int caplen);
	virtual void UpdateEndpointVal(RecordVal* endp, int is_orig);
	virtual bool IsReuse(double t, const u_char* pkt);
	virtual unsigned int MemoryAllocation() const;

	void ICMPEvent(EventHandlerPtr f);
	void Describe(ODesc* d) const;

	RecordVal* BuildICMPVal();

	virtual void NextICMP(double t, const struct icmp* icmpp,
				int len, int caplen, const u_char*& data);

	RecordVal* ExtractICMPContext(int len, const u_char*& data);

	RecordVal* icmp_conn_val;
	int type;
	int code;
	int len;

	int request_len, reply_len;

	RuleMatcherState matcher_state;
};

class ICMP_Echo_Analyzer : public ICMP_Analyzer {
public:
	ICMP_Echo_Analyzer(Connection* conn);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new ICMP_Echo_Analyzer(conn); }

	static bool Available()	{ return icmp_echo_request || icmp_echo_reply; }

protected:
	ICMP_Echo_Analyzer()	{ }

	virtual void NextICMP(double t, const struct icmp* icmpp,
	                      int len, int caplen, const u_char*& data);
};

class ICMP_Context_Analyzer : public ICMP_Analyzer {
public:
	ICMP_Context_Analyzer(AnalyzerTag::Tag tag, Connection* conn)
		: ICMP_Analyzer(tag, conn)	{ }

protected:
	ICMP_Context_Analyzer()	{ }

	virtual void NextICMP(double t, const struct icmp* icmpp,
	                      int len, int caplen, const u_char*& data);
};

class ICMP_TimeExceeded_Analyzer : public ICMP_Context_Analyzer {
public:
	ICMP_TimeExceeded_Analyzer(Connection* conn)
		: ICMP_Context_Analyzer(AnalyzerTag::ICMP_TimeExceeded, conn)	{ }

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new ICMP_TimeExceeded_Analyzer(conn); }

	static bool Available() { return icmp_time_exceeded; }

protected:
	ICMP_TimeExceeded_Analyzer()	{ }
};

class ICMP_Unreachable_Analyzer : public ICMP_Context_Analyzer {
public:
	ICMP_Unreachable_Analyzer(Connection* conn)
		: ICMP_Context_Analyzer(AnalyzerTag::ICMP_Unreachable, conn)	{ }

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new ICMP_Unreachable_Analyzer(conn); }

	static bool Available() { return icmp_unreachable; }

protected:
	ICMP_Unreachable_Analyzer()	{ }
};


// Returns the counterpart type to the given type (e.g., the counterpart
// to ICMP_ECHOREPLY is ICMP_ECHO).
extern int ICMP_counterpart(int icmp_type, int icmp_code, bool& is_one_way);

#endif
