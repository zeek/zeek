
#ifndef BRO_HILTI_PAC2ANALYZER_H
#define BRO_HILTI_PAC2ANALYZER_H

#include "../TCP.h"
#include "../UDP.h"

struct __binpac_parser;
struct __hlt_bytes;
struct __hlt_exception;

class Analyzer;

namespace bro {
namespace hilti {

class Pac2_Analyzer {
public:
	Pac2_Analyzer(analyzer::Analyzer* analyzer);
	virtual ~Pac2_Analyzer();

	void Init();
	void Done();

	// Returns:
	//    -1: Parsing yielded waiting for more input.
	//     0: Parsing failed, not more input will be accepted.
	//     1: Parsing finished, not more input will be accepted.
	int FeedChunk(int len, const u_char* data, bool is_orig, bool eod);

	void FlipRoles();

	struct Cookie {
		analyzer::Analyzer* analyzer;
		bool is_orig;
	};

protected:
	virtual void ParseError(const string& msg, bool is_orig);

private:
	struct Endpoint {
		__binpac_parser* parser;
		__hlt_bytes* data;
		__hlt_exception* resume;
		Cookie cookie;
		};

	Endpoint orig;
	Endpoint resp;
};

class Pac2_TCP_Analyzer : public Pac2_Analyzer, public TCP_ApplicationAnalyzer {
public:
	Pac2_TCP_Analyzer(Connection* conn);
	virtual ~Pac2_TCP_Analyzer();

	// Overriden from Analyzer.
	void Init() override;
	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(int seq, int len, bool orig) override;
	void EndOfData(bool is_orig) override;
	void FlipRoles() override;

	// Overriden from TCP_ApplicationAnalyzer.
	void EndpointEOF(bool is_orig) override;
	void ConnectionClosed(TCP_Endpoint* endpoint,
					TCP_Endpoint* peer, int gen_event);
	void ConnectionFinished(int half_finished) override;
	void ConnectionReset() override;
	void PacketWithRST() override;

	static Analyzer* InstantiateAnalyzer(Connection* conn);

private:
	bool skip_orig;
	bool skip_resp;
};

class Pac2_UDP_Analyzer : public Pac2_Analyzer, public analyzer::Analyzer {
public:
	Pac2_UDP_Analyzer(Connection* conn);
	virtual ~Pac2_UDP_Analyzer();

	// Overriden from Analyzer.
	void Init() override;
	void Done() override;
	void DeliverPacket(int len, const u_char* data, bool orig,
			   int seq, const IP_Hdr* ip, int caplen) override;
	void Undelivered(int seq, int len, bool orig) override;
	void EndOfData(bool is_orig) override;
	void FlipRoles() override;

	static Analyzer* InstantiateAnalyzer(Connection* conn);
};

}
}


#endif

