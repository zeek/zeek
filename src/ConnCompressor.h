// $Id: ConnCompressor.h 6008 2008-07-23 00:24:22Z vern $
//
// The ConnCompressor keeps track of the first packet seen for a conn_id using
// only a minimal amount of memory. This helps us to avoid instantiating
// full Connection objects for never-established sessions.
//
// TCP only.

#ifndef CONNCOMPRESSOR_H
#define CONNCOMPRESSOR_H

#include "Conn.h"
#include "Dict.h"
#include "NetVar.h"
#include "TCP.h"

class ConnCompressor {
public:
	ConnCompressor();
	~ConnCompressor();

	// Handle next packet.  Returns 0 if packet in handled internally.
	// Takes ownership of key.
	Connection* NextPacket(double t, HashKey* k, const IP_Hdr* ip_hdr,
			const struct pcap_pkthdr* hdr, const u_char* const pkt);

	// Look up a connection.  Returns non-nil for connections for
	// which a Connection object has already been instantiated.
	Connection* Lookup(HashKey* k)
		{
		ConnData* c = conns.Lookup(k);
		return c && IsConnPtr(c) ? MakeConnPtr(c) : 0;
		}

	// Inserts connection into compressor.  If another entry with this key
	// already exists, it's replaced.  If that was a full connection, it is
	// also returned.
	Connection* Insert(Connection* c);

	// Remove all state belonging to the given connection.  Returns
	// true if the connection was found in the compressor's table,
	// false if not.
	bool Remove(HashKey* k);

	// Flush state.
	void Drain();

	struct Sizes {
		// Current number of already fully instantiated connections.
		unsigned int connections;

		// Total number of fully instantiated connections.
		unsigned int connections_total;

		// Current number of seen but non-yet instantiated connections.
		unsigned int pending_valid;

		// Total number of seen but non-yet instantiated connections.
		unsigned int pending_total;

		// Total number of all entries in pending list (some a which
		// may already been invalid, but not yet removed from memory).
		unsigned int pending_in_mem;

		// Total number of hash table entires
		// (should equal connections + pending_valid)
		unsigned int hash_table_size;

		// Total memory usage;
		unsigned int memory;
	};

	const Sizes& Size()
		{ sizes.hash_table_size = conns.Length(); return sizes; }

	unsigned int MemoryAllocation() const	{ return sizes.memory; }

	// As long as we have only seen packets from one side, we just
	// store a PendingConn.
	struct PendingConn {
		// True if the block is indeed a PendingConn (see below).
		unsigned int is_pending:1;

		// Whether roles in key are flipped.
		unsigned int ip1_is_src:1;

		unsigned int invalid:1;	// deleted
		int window_scale:4;
		unsigned int SYN:1;
		unsigned int FIN:1;
		unsigned int RST:1;
		unsigned int ACK:1;

		double time;
		ConnID::Key key;
		uint32 seq;
		uint32 ack;
		hash_t hash;
		uint16 window;
	};

private:
	// Helpers to extract addrs/ports from PendingConn.

	const uint32* SrcAddr(const PendingConn* c)
		{ return c->ip1_is_src ? c->key.ip1 : c->key.ip2; }
	const uint32* DstAddr(const PendingConn* c)
		{ return c->ip1_is_src ? c->key.ip2 : c->key.ip1; }

	uint16 SrcPort(const PendingConn* c)
		{ return c->ip1_is_src ? c->key.port1 : c->key.port2; }
	uint16 DstPort(const PendingConn* c)
		{ return c->ip1_is_src ? c->key.port2 : c->key.port1; }


	// Called for the first packet in a connection.
	Connection* FirstFromOrig(double t, HashKey* key,
					const IP_Hdr* ip, const tcphdr* tp);

	// Called for more packets from the orginator w/o seeing a response.
	Connection* NextFromOrig(PendingConn* pending,
				double t, HashKey* key, const tcphdr* tp);

	// Called for the first response packet. Instantiates a Connection.
	Connection* Response(PendingConn* pending, double t, HashKey* key,
					const IP_Hdr* ip, const tcphdr* tp);

	// Instantiates a full TCP connection (invalidates pending connection).
	Connection* Instantiate(HashKey* key, PendingConn* pending);

	// Same but based on packet.
	Connection* Instantiate(double t, HashKey* key, const IP_Hdr* ip);

	// Fills the attributes of a PendingConn based on the given arguments.
	void PktHdrToPendingConn(double time, const HashKey* key,
		const IP_Hdr* ip, const struct tcphdr* tp, PendingConn* c);

	// Fakes a TCP packet based on the available information.
	const IP_Hdr* PendingConnToPacket(const PendingConn* c);

	// For changing the timestamp of PendingConn - allocates a new one,
	// sets the given time, and copies all other data from old.
	PendingConn* MoveState(double time, PendingConn* old);

	// Construct a TCP-flags byte.
	uint8 MakeFlags(const PendingConn* c) const;

	// Allocate room for a new (Ext)PendingConn.
	PendingConn* MakeNewState(double t);

	// Expire PendingConns.
	void DoExpire(double t);

	// Remove all state belonging to the given connection.
	void Invalidate(HashKey* k);

	// Sends the given connection_* event.  If orig_state is
	// TCP_ENDPOINT__INACTIVE, tries to guess a better one based
	// on pending.  If arg in non-nil, it will be used as the
	// *first* argument of the event call (this is for conn_weird()).
	void Event(const PendingConn* pending, double t,
			const EventHandlerPtr& event, int orig_state,
			int orig_size, int resp_state, Val* arg = 0);

	void Weird(const PendingConn* pending, double t, const char* msg)
		{
		if ( conn_weird )
			Event(pending, t, conn_weird, TCP_ENDPOINT_INACTIVE, 0,
				TCP_ENDPOINT_INACTIVE, new StringVal(msg));
		else
			fprintf(stderr, "%.06f weird: %s\n", t, msg);
		}

	static const int BLOCK_SIZE = 16 * 1024;

	// The memory managment for PendConns.
	struct Block {
		double time;
		Block* prev;
		Block* next;
		int bytes_used;
		unsigned char data[BLOCK_SIZE];
	};

	// In the connection hash table, we store pointers to both PendingConns
	// and Connections. Thus, we need a way to differentiate between
	// these two types. To avoid an additional indirection, we use a little
	// hack: a pointer retrieved from the table is interpreted as a
	// PendingConn first. However, if is_pending is false, it's in fact a
	// Connection which starts at offset 4. The methods below help to
	// implement this scheme transparently. An "operator new" in
	// Connection takes care of building Connection's accordingly.
	typedef PendingConn ConnData;
	declare(PDict, ConnData);
	typedef PDict(ConnData) ConnMap;
	ConnMap conns;

	static ConnData* MakeMapPtr(PendingConn* c)
		{ assert(c->is_pending); return c; }

	static ConnData* MakeMapPtr(Connection* c)
		{
		ConnData* p = (ConnData*) (((char*) c) - 4);
		assert(!p->is_pending);
		return p;
		}

	static PendingConn* MakePendingConnPtr(ConnData* c)
		{ assert(c->is_pending); return c; }

	static Connection* MakeConnPtr(ConnData* c)
		{
		assert(!c->is_pending);
		return (Connection*) (((char*) c) + 4);
		}

	static bool IsConnPtr(ConnData* c)
		{ return ! c->is_pending; }

	// New blocks are inserted at the end.
	Block* first_block;
	Block* last_block;

	// If we have already expired some entries in a block,
	// this points to the first non-expired.
	unsigned char* first_non_expired;

	// Last "connection" that we have build.
	RecordVal* conn_val;

	// Statistics.
	Sizes sizes;
	};

extern ConnCompressor* conn_compressor;

#endif
