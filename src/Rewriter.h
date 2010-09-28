// $Id:$
//
// See the file "COPYING" in the main distribution directory for copyright.

#ifndef rewriter_h
#define rewriter_h

class TracePacket;

class Rewriter {
public:
	virtual ~Rewriter()	{};

	virtual void Done()	{};

	virtual void WriteData(int is_orig, int len, const u_char* data) = 0;
	virtual void WriteData(int is_orig, const char* data) = 0;
	virtual void WriteData(int is_orig, int len, const char* data) = 0;
	virtual void WriteData(int is_orig, const BroString* str) = 0;

	virtual void Push(int is_orig) = 0;

	virtual void AbortPackets(int apply_to_future) = 0;
	virtual void CommitPackets(int apply_to_future) = 0;

	virtual unsigned int ReserveSlot() = 0;
	virtual int SeekSlot(unsigned int slot) = 0;
	virtual int ReturnFromSlot() = 0;
	virtual int ReleaseSlot(unsigned int slot) = 0;

	// Needed by all rewriters.
	virtual TracePacket* CurrentPacket() const = 0;
	virtual TracePacket* RewritePacket() const = 0;

	// Whether to not anonymize client/server IP addresses.
	virtual int LeaveAddrInTheClear(int is_orig) = 0;
};

extern Rewriter* get_trace_rewriter(Val* conn_val);
extern Rewriter* get_trace_rewriter(Connection* conn);

// This is the actual packet.
class TracePacket {
public:
	virtual ~TracePacket()	{ }

	virtual RecordVal* PacketVal() = 0;
	virtual double TimeStamp() const = 0;
};

#endif
