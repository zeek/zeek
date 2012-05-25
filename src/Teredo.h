#ifndef Teredo_h
#define Teredo_h

#include "Analyzer.h"
#include "NetVar.h"

class Teredo_Analyzer : public Analyzer {
public:
	Teredo_Analyzer(Connection* conn) : Analyzer(AnalyzerTag::Teredo, conn)
		{}

	virtual ~Teredo_Analyzer()
		{}

	virtual void Done();

	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					int seq, const IP_Hdr* ip, int caplen);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new Teredo_Analyzer(conn); }

	static bool Available()
		//TODO: specific option to turn off Teredo analysis?
		{ return BifConst::Tunnel::max_depth > 0; }

protected:
	friend class AnalyzerTimer;
	void ExpireTimer(double t);
};

class TeredoEncapsulation {
public:
	TeredoEncapsulation(Connection* c)
		: inner_ip(0), origin_indication(0), auth(0), conn(c)
		{}

	/**
	 * Returns whether input data parsed as a valid Teredo encapsulation type.
	 * If it was valid, the len argument is decremented appropriately.
	 */
	bool Parse(const u_char* data, int& len)
		{ return DoParse(data, len, false, false); }

	const u_char* InnerIP() const
		{ return inner_ip; }

	const u_char* OriginIndication() const
		{ return origin_indication; }

	const u_char* Authentication() const
		{ return auth; }

protected:
	bool DoParse(const u_char* data, int& len, bool found_orig, bool found_au);

	const u_char* inner_ip;
	const u_char* origin_indication;
	const u_char* auth;
	Connection* conn;
};

#endif
