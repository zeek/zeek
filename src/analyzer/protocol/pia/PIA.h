// An analyzer for application-layer protocol-detection.

#ifndef ANALYZER_PROTOCOL_PIA_PIA_H
#define ANALYZER_PROTOCOL_PIA_PIA_H

#include "analyzer/Analyzer.h"
#include "analyzer/protocol/tcp/TCP.h"

class RuleEndpointState;

namespace analyzer { namespace pia {

// Abstract PIA class providing common functionality for both TCP and UDP.
// Accepts only packet input.
//
// Note that the PIA provides our main interface to the signature engine and
// also keeps the matching state.  This is because (i) it needs to match
// itself, and (ii) in case of tunnel-decapsulation we may have multiple
// PIAs and then each needs its own matching-state.
class PIA : public RuleMatcherState {
public:
	PIA(analyzer::Analyzer* as_analyzer);
	virtual ~PIA();

	// Called when PIA wants to put an Analyzer in charge.  rule is the
	// signature that triggered the activitation, if any.
	virtual void ActivateAnalyzer(analyzer::Tag tag,
					const Rule* rule = 0) = 0;

	// Called when PIA wants to remove an Analyzer.
	virtual void DeactivateAnalyzer(analyzer::Tag tag) = 0;

	void Match(Rule::PatternType type, const u_char* data, int len,
			bool is_orig, bool bol, bool eol, bool clear_state);

	void ReplayPacketBuffer(analyzer::Analyzer* analyzer);

	// Children are also derived from Analyzer. Return this object
	// as pointer to an Analyzer.
	analyzer::Analyzer* AsAnalyzer()	{ return as_analyzer; }

protected:
	void PIA_Done();
	void PIA_DeliverPacket(int len, const u_char* data, bool is_orig,
				int seq, const IP_Hdr* ip, int caplen);

	enum State { INIT, BUFFERING, MATCHING_ONLY, SKIPPING } state;

	// Buffers one chunk of data.  Used both for packet payload (incl.
	// sequence numbers for TCP) and chunks of a reassembled stream.
	struct DataBlock {
		const u_char* data;
		bool is_orig;
		int len;
		int seq;
		DataBlock* next;
	};

	struct Buffer {
		Buffer() { head = tail = 0; size = 0; state = INIT; }

		DataBlock* head;
		DataBlock* tail;
		int size;
		State state;
	};

	void AddToBuffer(Buffer* buffer, int seq, int len,
				const u_char* data, bool is_orig);
	void AddToBuffer(Buffer* buffer, int len,
				const u_char* data, bool is_orig);
	void ClearBuffer(Buffer* buffer);

	DataBlock* CurrentPacket()	{ return &current_packet; }

	void DoMatch(const u_char* data, int len, bool is_orig, bool bol,
			bool eol, bool clear_state, const IP_Hdr* ip = 0);

	void SetConn(Connection* c)	{ conn = c; }

	Buffer pkt_buffer;

private:
	analyzer::Analyzer* as_analyzer;
	Connection* conn;
	DataBlock current_packet;
};

// PIA for UDP.
class PIA_UDP : public PIA, public analyzer::Analyzer {
public:
	PIA_UDP(Connection* conn)
	: PIA(this), Analyzer("PIA_UDP", conn)
		{ SetConn(conn); }
	virtual ~PIA_UDP()	{ }

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new PIA_UDP(conn); }

protected:
	virtual void Done()
		{
		Analyzer::Done();
		PIA_Done();
		}

	virtual void DeliverPacket(int len, const u_char* data, bool is_orig,
					int seq, const IP_Hdr* ip, int caplen)
		{
		Analyzer::DeliverPacket(len, data, is_orig, seq, ip, caplen);
		PIA_DeliverPacket(len, data, is_orig, seq, ip, caplen);
		}

	virtual void ActivateAnalyzer(analyzer::Tag tag, const Rule* rule);
	virtual void DeactivateAnalyzer(analyzer::Tag tag);
};

// PIA for TCP.  Accepts both packet and stream input (and reassembles
// packets before passing payload on to children).
class PIA_TCP : public PIA, public tcp::TCP_ApplicationAnalyzer {
public:
	PIA_TCP(Connection* conn)
		: PIA(this), tcp::TCP_ApplicationAnalyzer("PIA_TCP", conn)
		{ stream_mode = false; SetConn(conn); }

	virtual ~PIA_TCP();

	virtual void Init();

	// The first packet for each direction of a connection is passed
	// in here.
	//
	// (This is a bit crude as it doesn't really fit nicely into the
	// analyzer interface.  Yet we need it for initializing the packet
	// matcher in the case that we already get reassembled input,
	// and making it part of the general analyzer interface seems
	// to be unnecessary overhead.)
	void FirstPacket(bool is_orig, const IP_Hdr* ip);

	void ReplayStreamBuffer(analyzer::Analyzer* analyzer);

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new PIA_TCP(conn); }

protected:
	virtual void Done()
		{
		Analyzer::Done();
		PIA_Done();
		}

	virtual void DeliverPacket(int len, const u_char* data, bool is_orig,
					int seq, const IP_Hdr* ip, int caplen)
		{
		Analyzer::DeliverPacket(len, data, is_orig, seq, ip, caplen);
		PIA_DeliverPacket(len, data, is_orig, seq, ip, caplen);
		}

	virtual void DeliverStream(int len, const u_char* data, bool is_orig);
	virtual void Undelivered(int seq, int len, bool is_orig);

	virtual void ActivateAnalyzer(analyzer::Tag tag,
					const Rule* rule = 0);
	virtual void DeactivateAnalyzer(analyzer::Tag tag);

private:
	// FIXME: Not sure yet whether we need both pkt_buffer and stream_buffer.
	// In any case, it's easier this way...
	Buffer stream_buffer;

	bool stream_mode;
};

} } // namespace analyzer::* 

#endif
