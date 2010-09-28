// $Id:$
//
// Main analyzer interface.

#ifndef ANALYZER_H
#define ANALYZER_H

#include <list>

#include "AnalyzerTags.h"
#include "Conn.h"
#include "Obj.h"

class DPM;
class PIA;
class Analyzer;
typedef list<Analyzer*> analyzer_list;

typedef void (Analyzer::*analyzer_timer_func)(double t);

// FIXME: This is a copy of ConnectionTimer, which we may eventually be
// able to get rid of.
class AnalyzerTimer : public Timer {
public:
	AnalyzerTimer(Analyzer* arg_analyzer, analyzer_timer_func arg_timer,
			double arg_t, int arg_do_expire, TimerType arg_type)
		: Timer(arg_t, arg_type)
		{ Init(arg_analyzer, arg_timer, arg_do_expire); }
	virtual ~AnalyzerTimer();

	void Dispatch(double t, int is_expire);

protected:
	AnalyzerTimer()	{}

	void Init(Analyzer* analyzer, analyzer_timer_func timer, int do_expire);

	Analyzer* analyzer;
	analyzer_timer_func timer;
	int do_expire;
};


// Main analyzer interface.
//
// Each analyzer is part of a tree, having a parent analyzer and an
// arbitrary number of child analyzers.  Each analyzer also has a list of
// *suppport analyzers*.  All its input first passes through this list of
// support analyzers, which can perform arbitrary preprocessing.  Support
// analyzers share the same interface as regular analyzers, except that
// they are unidirectional, i.e., they see only one side of a connection.
//
// When overiding any of these methods, always make sure to call the
// base-class version first.

class SupportAnalyzer;
class OutputHandler;

class Analyzer {
public:
	Analyzer(AnalyzerTag::Tag tag, Connection* conn);
	virtual ~Analyzer();

	virtual void Init();
	virtual void Done();

	// Pass data to the analyzer (it's automatically passed through its
	// support analyzers first).  We have packet-wise and stream-wise
	// interfaces.  For the packet-interface, some analyzers may require
	// more information than others, so IP/caplen and seq may or may
	// not be set.
	void NextPacket(int len, const u_char* data, bool orig,
			int seq = -1, const IP_Hdr* ip = 0, int caplen = 0);
	void NextStream(int len, const u_char* data, bool is_orig);

	// Used for data that can't be delivered (e.g., due to a previous
	// sequence hole/gap).
	void NextUndelivered(int seq, int len, bool is_orig);

	// Report message boundary. (See EndOfData() below.)
	void NextEndOfData(bool orig);

	// Pass data on to all child analyzer(s).  For SupportAnalyzers (see
	// below), this is overridden to pass it on to the next sibling (or
	// finally to the parent, if it's the last support analyzer).
	//
	// If we have an associated OutputHandler (see below), the data is
	// additionally passed to that, too. For SupportAnalyzers, it is *only*
	// delivered to the OutputHandler.
	virtual void ForwardPacket(int len, const u_char* data,
					bool orig, int seq,
					const IP_Hdr* ip, int caplen);
	virtual void ForwardStream(int len, const u_char* data, bool orig);
	virtual void ForwardUndelivered(int seq, int len, bool orig);

	// Report a message boundary to all child analyzers
	virtual void ForwardEndOfData(bool orig);

	AnalyzerID GetID() const	{ return id; }
	Connection* Conn() const	{ return conn; }

	// An OutputHandler can be used to get access to data extracted by this
	// analyzer (i.e., all data which is passed to
	// Forward{Packet,Stream,Undelivered}).  We take the ownership of
	// the handler.
	class OutputHandler {
	public:
		virtual	~OutputHandler() { }

		virtual void DeliverPacket(int len, const u_char* data,
						bool orig, int seq,
						const IP_Hdr* ip, int caplen)
			{ }
		virtual void DeliverStream(int len, const u_char* data,
						bool orig)	{ }
		virtual void Undelivered(int seq, int len, bool orig)	{ }
	};

	OutputHandler* GetOutputHandler() const	{ return output_handler; }
	void SetOutputHandler(OutputHandler* handler)
		{ output_handler = handler; }

	// If an analyzer was triggered by a signature match, this returns the
	// name of the signature; nil if not.
	const Rule* Signature() const		{ return signature; }
	void SetSignature(const Rule* sig)	{ signature = sig; }

	void SetSkip(bool do_skip)		{ skip = do_skip; }
	bool Skipping() const			{ return skip; }

	bool IsFinished() const 		{ return finished; }

	AnalyzerTag::Tag GetTag() const		{ return tag; }
	const char* GetTagName() const;
	static AnalyzerTag::Tag GetTag(const char* tag);
	static const char* GetTagName(AnalyzerTag::Tag tag);
	static bool IsAvailable(AnalyzerTag::Tag tag)
		{ return analyzer_configs[tag].available(); }

	// Management of the tree.
	//
	// We immediately discard an added analyzer if there's already a child
	// of the same type.
	void AddChildAnalyzer(Analyzer* analyzer)
		{ AddChildAnalyzer(analyzer, true); }
	Analyzer* AddChildAnalyzer(AnalyzerTag::Tag tag);

	void RemoveChildAnalyzer(Analyzer* analyzer);
	void RemoveChildAnalyzer(AnalyzerID id);

	bool HasChildAnalyzer(AnalyzerTag::Tag tag);

	// Recursive; returns nil if not found.
	Analyzer* FindChild(AnalyzerID id);

	// Recursive; returns first found, or nil.
	Analyzer* FindChild(AnalyzerTag::Tag tag);

	const analyzer_list& GetChildren()	{ return children; }

	Analyzer* Parent() const	{ return parent; }
	void SetParent(Analyzer* p)	{ parent = p; }

	// Remove this child analyzer from the parent's list.
	void Remove()	{ assert(parent); parent->RemoveChildAnalyzer(this); }

	// Management of support analyzers.  Support analyzers are associated
	// with a direction, and will only see data in the corresponding flow.
	//
	// We immediately discard an added analyzer if there's already a child
	// of the same type for the same direction.

	// Adds to tail of list.
	void AddSupportAnalyzer(SupportAnalyzer* analyzer);

	void RemoveSupportAnalyzer(SupportAnalyzer* analyzer);

	// These are the methods where the analyzer actually gets its input.
	// Each analyzer has only to implement the schemes it supports.

	// Packet-wise (or more generally chunk-wise) input.  "data" points
	// to the payload that the analyzer is supposed to examine.  If it's
	// part of a full packet, "ip" points to its IP header.  An analyzer
	// may or may not require to be given the full packet (and its caplen)
	// as well.
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					int seq, const IP_Hdr* ip, int caplen);

	// Stream-wise payload input.
	virtual void DeliverStream(int len, const u_char* data, bool orig);

	// If a parent analyzer can't turn a sequence of packets into a stream
	// (e.g., due to holes), it can pass the remaining data through this
	// method to the child.
	virtual void Undelivered(int seq, int len, bool orig);

	// Report a message boundary.  This is a generic method that can be used
	// by specific Analyzers if all data of a message has been delivered,
	// e.g., to report that HTTP body has been delivered completely by the
	// HTTP analyzer before it starts with the next body. EndOfData() is
	// automatically generated by the analyzer's Done() method.
	virtual void EndOfData(bool is_orig);

	// Occasionally we may find during analysis that we got the direction
	// of the connection wrong.  In these cases, this method is called
	// to swap state if necessary.  This will not happen after payload
	// has already been passed on, so most analyzers don't need to care.
	virtual void FlipRoles();

	// Feedback about protocol conformance, to be called by the
	// analyzer's processing.  The methods raise the correspondiong
	// protocol_confirmation and protocol_violation events.

	// Report that we believe we're parsing the right protocol.  This
	// should be called as early as possible during a connection's
	// life-time. The protocol_confirmed event is only raised once per
	// analyzer, even if the method is called multiple times.
	virtual void ProtocolConfirmation();

	// Report that we found a significant protocol violation which might
	// indicate that the analyzed data is in fact not the expected
	// protocol.  The protocol_violation event is raised once per call to
	// this method so that the script-level may build up some notion of
	// how "severely" protocol semantics are violated.
	virtual void ProtocolViolation(const char* reason,
					const char* data = 0, int len = 0);

	// Returns true if the analyzer or one of its children is rewriting
	// the trace.
	virtual int RewritingTrace();

	virtual unsigned int MemoryAllocation() const;

	// The following methods are proxies: calls are directly forwarded
	// to the connection instance.  These are for convenience only,
	// allowing us to reuse more of the old analyzer code unchanged.
	RecordVal* BuildConnVal()
		{ return conn->BuildConnVal(); }
	void Event(EventHandlerPtr f, const char* name = 0)
		{ conn->Event(f, this, name); }
	void Event(EventHandlerPtr f, Val* v1, Val* v2 = 0)
		{ conn->Event(f, this, v1, v2); }
	void ConnectionEvent(EventHandlerPtr f, val_list* vl)
		{ conn->ConnectionEvent(f, this, vl); }
	void Weird(const char* name)	{ conn->Weird(name); }
	void Weird(const char* name, const char* addl)
		{ conn->Weird(name, addl); }
	void Weird(const char* name, int addl_len, const char* addl)
		{ conn->Weird(name, addl_len, addl); };

	// Factory function to instantiate new analyzers.
	static Analyzer* InstantiateAnalyzer(AnalyzerTag::Tag tag, Connection* c);

protected:
	friend class DPM;
	friend class Connection;
	friend class AnalyzerTimer;
	friend class TCP_ApplicationAnalyzer;

	Analyzer()	{ }

	// Associates a connection with this analyzer.  Must be called if
	// we're using the default ctor.
	void SetConnection(Connection* c)	{ conn = c; }

	// Creates the given timer to expire at time t.  If do_expire
	// is true, then the timer is also evaluated when Bro terminates,
	// otherwise not.
	void AddTimer(analyzer_timer_func timer, double t, int do_expire,
			TimerType type);

	void RemoveTimer(Timer* t);
	void CancelTimers();

	bool HasSupportAnalyzer(AnalyzerTag::Tag tag, bool orig);

	void AddChildAnalyzer(Analyzer* analyzer, bool init);
	void InitChildren();
	void AppendNewChildren();

private:
	AnalyzerTag::Tag tag;
	AnalyzerID id;

	Connection* conn;
	Analyzer* parent;
	const Rule* signature;
	OutputHandler* output_handler;

	analyzer_list children;
	SupportAnalyzer* orig_supporters;
	SupportAnalyzer* resp_supporters;

	analyzer_list new_children;

	bool protocol_confirmed;

	timer_list timers;
	bool timers_canceled;
	bool skip;
	bool finished;

	static AnalyzerID id_counter;

	typedef bool (*available_callback)();
	typedef Analyzer* (*factory_callback)(Connection* conn);
	typedef bool (*match_callback)(Connection*);

	struct Config {
		AnalyzerTag::Tag tag;
		const char* name;
		factory_callback factory;
		available_callback available;
		match_callback match;
		bool partial;
	};

	// Table of analyzers.
	static const Config analyzer_configs[];

};

#define ADD_ANALYZER_TIMER(timer, t, do_expire, type) \
	AddTimer(analyzer_timer_func(timer), (t), (do_expire), (type))

#define LOOP_OVER_CHILDREN(var) \
	for ( analyzer_list::iterator var = children.begin(); \
	      var != children.end(); var++ )

#define LOOP_OVER_CONST_CHILDREN(var) \
	for ( analyzer_list::const_iterator var = children.begin(); \
	      var != children.end(); var++ )

#define LOOP_OVER_GIVEN_CHILDREN(var, the_kids) \
	for ( analyzer_list::iterator var = the_kids.begin(); \
	      var != the_kids.end(); var++ )

class SupportAnalyzer : public Analyzer {
public:
	SupportAnalyzer(AnalyzerTag::Tag tag, Connection* conn, bool arg_orig)
		: Analyzer(tag, conn)	{ orig = arg_orig; sibling = 0; }

	virtual ~SupportAnalyzer() {}

	bool IsOrig() const 	{ return orig; }

	virtual void ForwardPacket(int len, const u_char* data, bool orig,
					int seq, const IP_Hdr* ip, int caplen);
	virtual void ForwardStream(int len, const u_char* data, bool orig);
	virtual void ForwardUndelivered(int seq, int len, bool orig);

	SupportAnalyzer* Sibling() const 	{ return sibling; }

protected:
	friend class Analyzer;

	SupportAnalyzer()	{ }
private:
	bool orig;

	// Points to next support analyzer in chain.  The list is managed by
	// parent analyzer.
	SupportAnalyzer* sibling;
};


class TransportLayerAnalyzer : public Analyzer {
public:
	TransportLayerAnalyzer(AnalyzerTag::Tag tag, Connection* conn)
		: Analyzer(tag, conn)	{ pia = 0; rewriter = 0; }

	virtual ~TransportLayerAnalyzer();

	virtual void Done();
	virtual void UpdateEndpointVal(RecordVal* endp, int is_orig) = 0;
	virtual bool IsReuse(double t, const u_char* pkt) = 0;

	virtual void SetContentsFile(unsigned int direction, BroFile* f);
	virtual BroFile* GetContentsFile(unsigned int direction) const;

	void SetPIA(PIA* arg_PIA)	{ pia = arg_PIA; }
	PIA* GetPIA() const		{ return pia; }

	Rewriter* TraceRewriter()	{ return rewriter; }

	// Takes ownership.
	void SetTraceRewriter(Rewriter* r);

	// Raises packet_contents event.
	void PacketContents(const u_char* data, int len);

protected:
	TransportLayerAnalyzer()	{ }

private:
	PIA* pia;
	Rewriter* rewriter;
};

#endif
