// $Id: RemoteSerializer.h 6951 2009-12-04 22:23:28Z vern $
//
// Communication between two Bro's.

#ifndef REMOTE_SERIALIZER
#define REMOTE_SERIALIZER

#include "Dict.h"
#include "List.h"
#include "Serializer.h"
#include "IOSource.h"
#include "Stats.h"
#include "File.h"

// All IP arguments are in host byte-order.
// FIXME: Change this to network byte order

class IncrementalSendTimer;

// This class handles the communication done in Bro's main loop.
class RemoteSerializer : public Serializer, public IOSource {
public:
	RemoteSerializer();
	virtual ~RemoteSerializer();

	// Initialize the remote serializer (calling this will fork).
	void Init();

	// FIXME: Use SourceID directly (or rename everything to Peer*).
	typedef SourceID PeerID;
	static const PeerID PEER_LOCAL = SOURCE_LOCAL;
	static const PeerID PEER_NONE = SOURCE_LOCAL;

	// Connect to host (returns PEER_NONE on error).
	PeerID Connect(addr_type ip, uint16 port, const char* our_class, double retry, bool use_ssl);

	// Request all events matching pattern from remote side.
	bool RequestEvents(PeerID peer, RE_Matcher* pattern);

	// Request synchronization of IDs with remote side.  If auth is true,
	// we consider our current state to authoritative and send it to
	// the peer right after the handshake.
	bool RequestSync(PeerID peer, bool auth);

	// Sets flag whether we're accepting state from this peer
	// (default: yes).
	bool SetAcceptState(PeerID peer, bool accept);

	// Sets compression level (0-9, 0 is defaults and means no compression)
	bool SetCompressionLevel(PeerID peer, int level);

	// Signal the other side that we have finished our part of
	// the initial handshake.
	bool CompleteHandshake(PeerID peer);

	// Start to listen.
	bool Listen(addr_type ip, uint16 port, bool expect_ssl);

	// Stop it.
	bool StopListening();

	// Broadcast the event/function call.
	bool SendCall(SerialInfo* info, const char* name, val_list* vl);

	// Send the event/function call (only if handshake completed).
	bool SendCall(SerialInfo* info, PeerID peer, const char* name, val_list* vl);

	// Broadcasts the access (only if handshake completed).
	bool SendAccess(SerialInfo* info, const StateAccess& access);

	// Send the access.
	bool SendAccess(SerialInfo* info, PeerID pid, const StateAccess& access);

	// Sends ID.
	bool SendID(SerialInfo* info, PeerID peer, const ID& id);

	// Sends the internal connection state.
	bool SendConnection(SerialInfo* info, PeerID peer, const Connection& c);

	// Send capture filter.
	bool SendCaptureFilter(PeerID peer, const char* filter);

	// Send packet.
	bool SendPacket(SerialInfo* info, PeerID peer, const Packet& p);

	// Broadcast packet.
	bool SendPacket(SerialInfo* info, const Packet& p);

	// Broadcast ping.
	bool SendPing(PeerID peer, uint32 seq);

	// Broadcast remote print.
	bool SendPrintHookEvent(BroFile* f, const char* txt);

	// Synchronzizes time with all connected peers. Returns number of
	// current sync-point, or -1 on error.
	uint32 SendSyncPoint();
	void SendFinalSyncPoint();

	// Registers the ID to be &synchronized.
	void Register(ID* id);
	void Unregister(ID* id);

	// Stop/restart propagating state updates.
	void SuspendStateUpdates()	{ --propagate_accesses; }
	void ResumeStateUpdates()	{ ++propagate_accesses; }

	// Check for incoming events and queue them.
	bool Poll(bool may_block);

	// Returns the corresponding record (already ref'ed).
	RecordVal* GetPeerVal(PeerID id);

	// Log some statistics.
	void LogStats();

	// Return a 0-terminated array of built-in functions which,
	// when referenced, trigger the remote serializer's initialization.
	const char* const* GetBuiltins() const;

	// Tries to sent out all remaining data.
	// FIXME: Do we still need this?
	void Finish();

	// Overidden from IOSource:
	virtual void GetFds(int* read, int* write, int* except);
	virtual double NextTimestamp(double* local_network_time);
	virtual void Process();
	virtual TimerMgr::Tag* GetCurrentTag();
	virtual const char* Tag()	{ return "RemoteSerializer"; }

	// Gracefully finishes communication by first making sure that all
	// remaining data (parent & child) has been sent out.
	virtual bool Terminate();

#ifdef DEBUG_COMMUNICATION
	// Dump data recently read/written into files.
	void DumpDebugData();

	// Read dump file and interpret as message block.
	void ReadDumpAsMessageType(const char* file);

	// Read dump file and interpret as serialization.
	void ReadDumpAsSerialization(const char* file);
#endif

	enum LogLevel { LogInfo = 1, LogError = 2, };
	static void Log(LogLevel level, const char* msg);

protected:
	friend class PersistenceSerializer;
	friend class IncrementalSendTimer;

	// Maximum size of serialization caches.
	static const unsigned int MAX_CACHE_SIZE = 3000;

	// When syncing traces in pseudo-realtime mode, we wait this many
	// seconds after the final sync-point to make sure that all
	// remaining I/O gets propagated.
	static const unsigned int FINAL_SYNC_POINT_DELAY = 5;

	declare(PList, EventHandler);
	typedef PList(EventHandler) handler_list;

	struct Peer {
		PeerID id; // Unique ID (non-zero) per peer.

		// ### Fix: currently, we only work for IPv4.
		// addr_type ip;
		uint32 ip;

		uint16 port;
		handler_list handlers;
		RecordVal* val;		// Record of type event_source.
		SerializationCache* cache_in;	// One cache for each direction.
		SerializationCache* cache_out;

		// TCP-level state of the connection to the peer.
		// State of the connection to the peer.
		enum { INIT, PENDING, CONNECTED, CLOSING, CLOSED } state;

		// Current protocol phase of the connection (see RemoteSerializer.cc)
		enum { UNKNOWN, SETUP, HANDSHAKE, SYNC, RUNNING } phase;

		// Capabilities.
		static const int COMPRESSION = 1;
		static const int NO_CACHING = 2;
		static const int PID_64BIT = 4;
		static const int NEW_CACHE_STRATEGY = 8;

		// Constants to remember to who did something.
		static const int NONE = 0;
		static const int WE = 1;
		static const int PEER = 2;
		static const int BOTH = WE | PEER;

		static const int AUTH_WE = 4;
		static const int AUTH_PEER = 8;

		int sent_version;	// Who has sent the VERSION.
		int handshake_done;	// Who finished its handshake phase.
		int sync_requested;	// Who requested sync'ed state.

		bool orig;	// True if we connected to the peer.
		bool accept_state;	// True if we accept state from peer.
		bool send_state; // True if we're supposed to initially sent our state.
		int comp_level; // Compression level.

		// True if this peer triggered a net_suspend_processing().
		bool suspended_processing;

		uint32 caps;	// Capabilities announced by peer.
		int runtime;	// Runtime we got from the peer.
		int our_runtime;	// Our runtime as we told it to this peer.
		string peer_class;	// Class from peer ("" = no class).
		string our_class;	// Class we send the peer.
		uint32 sync_point;	// Highest sync-point received so far
		char* print_buffer;	// Buffer for remote print or null.
		int print_buffer_used;	// Number of bytes used in buffer.
	};

	// Shuts down remote serializer.
	void FatalError(const char* msg);

	enum LogSrc { LogChild = 1, LogParent = 2, LogScript = 3, };

	static void Log(LogLevel level, const char* msg, Peer* peer, LogSrc src = LogParent);

	virtual void ReportError(const char* msg);

	virtual void GotEvent(const char* name, double time,
				EventHandlerPtr event, val_list* args);
	virtual void GotFunctionCall(const char* name, double time,
				Func* func, val_list* args);
	virtual void GotID(ID* id, Val* val);
	virtual void GotStateAccess(StateAccess* s);
	virtual void GotTimer(Timer* t);
	virtual void GotConnection(Connection* c);
	virtual void GotPacket(Packet* packet);

	void Fork();

	bool DoMessage();
	bool ProcessConnected();
	bool ProcessSerialization();
	bool ProcessRequestEventsMsg();
	bool ProcessRequestSyncMsg();
	bool ProcessVersionMsg();
	bool ProcessLogMsg(bool is_error);
	bool ProcessStatsMsg();
	bool ProcessCaptureFilterMsg();
	bool ProcessPhaseDone();
	bool ProcessPingMsg();
	bool ProcessPongMsg();
	bool ProcessCapsMsg();
	bool ProcessSyncPointMsg();
	bool ProcessRemotePrint();

	Peer* AddPeer(uint32 ip, uint16 port, PeerID id = PEER_NONE);
	Peer* LookupPeer(PeerID id, bool only_if_connected);
	void RemovePeer(Peer* peer);
	bool IsConnectedPeer(PeerID id);
	void PeerDisconnected(Peer* peer);
	void PeerConnected(Peer* peer);
	RecordVal* MakePeerVal(Peer* peer);
	bool HandshakeDone(Peer* peer);
	bool IsActive();
	void SetupSerialInfo(SerialInfo* info, Peer* peer);
	bool CheckSyncPoints();
	void SendSyncPoint(uint32 syncpoint);
	bool PropagateAccesses()
		{
		return ignore_accesses ?
			propagate_accesses > 1 : propagate_accesses > 0;
		}

	bool CloseConnection(Peer* peer);

	bool SendAllSynchronized(Peer* peer, SerialInfo* info);
	bool SendCall(SerialInfo* info, Peer* peer, const char* name, val_list* vl);
	bool SendAccess(SerialInfo* info, Peer* peer, const StateAccess& access);
	bool SendID(SerialInfo* info, Peer* peer, const ID& id);
	bool SendCapabilities(Peer* peer);
	bool SendPacket(SerialInfo* info, Peer* peer, const Packet& p);

	void UnregisterHandlers(Peer* peer);
	void RaiseEvent(EventHandlerPtr event, Peer* peer, const char* arg = 0);
	bool EnterPhaseRunning(Peer* peer);
	bool FlushPrintBuffer(Peer* p);

	void ChildDied();
	void InternalCommError(const char* msg);

	// Communication helpers
	bool SendCMsgToChild(char msg_type, Peer* peer);
	bool SendToChild(char type, Peer* peer, char* str, int len = -1);
	bool SendToChild(char type, Peer* peer, int nargs, ...); // can send uints32 only
	bool SendToChild(ChunkedIO::Chunk* c);

private:
	enum { TYPE, ARGS } msgstate;	// current state of reading comm.
	Peer* current_peer;
	PeerID current_id;
	char current_msgtype;
	ChunkedIO::Chunk* current_args;

	id_list sync_ids;

	// FIXME: Check which of these are necessary...
	bool initialized;
	bool listening;
	int propagate_accesses;
	bool ignore_accesses;
	bool terminating;
	Peer* source_peer;
	PeerID id_counter;	// Keeps track of assigned IDs.
	uint32 current_sync_point;
	bool syncing_times;

	declare(PList, Peer);
	typedef PList(Peer) peer_list;
	peer_list peers;

	Peer* in_sync; // Peer we're currently syncing state with.
	peer_list sync_pending; // List of peers waiting to sync state.

	// Event buffer
	struct BufferedEvent {
		time_t time;
		PeerID src;
		EventHandlerPtr handler;
		val_list* args;
	};

	declare(PList, BufferedEvent);
	typedef PList(BufferedEvent) EventQueue;
	EventQueue events;

	// Packet buffer
	struct BufferedPacket {
		time_t time;
		Packet* p;
	};

	declare(PList, BufferedPacket);
	typedef PList(BufferedPacket) PacketQueue;
	PacketQueue packets;

	// Some stats
	struct Statistics {
		struct Pair {
		Pair() : in(0), out(0)	{}
			unsigned long in;
			unsigned long out;
			};

		Pair events; // actually events and function calls
		Pair accesses;
		Pair conns;
		Pair packets;
		Pair ids;
	} stats;

};

// This class handles the communication done in the forked child.
class SocketComm {
public:
	SocketComm();
	~SocketComm();

	void SetParentIO(ChunkedIO* arg_io)	{ io = arg_io; }

	void Run();	// does not return

	// Log some statistics (via pipe to parent).
	bool LogStats();

	// Log CPU usage (again via pipe to parent).
	bool LogProf();

protected:
	struct Peer {
		Peer()
			{
			id = 0;
			io = 0;
			ip = 0;
			port = 0;
			state = 0;
			connected = false;
			ssl = false;
			retry = 0;
			next_try = 0;
			compressor = false;
			}

		RemoteSerializer::PeerID id;
		ChunkedIO* io;
		uint32 ip;
		uint16 port;
		char state;
		bool connected;
		bool ssl;
		// If we get disconnected, reconnect after this many seconds.
		int retry;
		// Time of next connection attempt (0 if none).
		time_t next_try;
		// True if io is a CompressedChunkedIO.
		bool compressor;
	};

	bool Listen(uint32 ip, uint16 port, bool expect_ssl);
	bool AcceptConnection(int listen_fd);
	bool Connect(Peer* peer);
	bool CloseConnection(Peer* peer, bool reconnect);

	Peer* LookupPeer(RemoteSerializer::PeerID id, bool only_if_connected);

	bool ProcessRemoteMessage(Peer* peer);
	bool ProcessParentMessage();
	bool DoParentMessage();

	bool ProcessListen();
	bool ProcessConnectTo();
	bool ProcessCompress();

	void Log(const char* msg, Peer* peer = 0);

	// The connection to the peer will be closed.
	bool Error(const char* msg, Peer* peer);

	// If kill is true, this is a fatal error and we kill ourselves.
	void Error(const char* msg, bool kill = false);

	// Kill the current process.
	void Kill();

	// Check whether everything has been sent out.
	void CheckFinished();

	// Communication helpers.
	bool SendToParent(char type, Peer* peer, const char* str, int len = -1);
	bool SendToParent(char type, Peer* peer, int nargs, ...); // can send uints32 only
	bool SendToParent(ChunkedIO::Chunk* c);
	bool SendToPeer(Peer* peer, char type, const char* str, int len = -1);
	bool SendToPeer(Peer* peer, char type, int nargs, ...); // can send uints32 only
	bool SendToPeer(Peer* peer, ChunkedIO::Chunk* c);
	bool ProcessParentCompress();
	bool ProcessPeerCompress(Peer* peer);
	bool ForwardChunkToParent(Peer* p, ChunkedIO::Chunk* c);
	bool ForwardChunkToPeer();
	const char* MakeLogString(const char* msg, Peer *peer);

	// Peers we are communicating with:
	declare(PList, Peer);
	typedef PList(Peer) peer_list;

	RemoteSerializer::PeerID id_counter;
	peer_list peers;

	ChunkedIO* io;	// I/O to parent

	// Current state of reading from parent.
	enum { TYPE, ARGS } parent_msgstate;
	Peer* parent_peer;
	RemoteSerializer::PeerID parent_id;
	char parent_msgtype;
	ChunkedIO::Chunk* parent_args;

	int listen_fd_clear;
	int listen_fd_ssl;

	// If the port we're trying to bind to is already in use, we will retry
	// it regularly.
	uint32 listen_if;	// Fix: only supports IPv4
	uint16 listen_port;
	bool listen_ssl;
	time_t listen_next_try;
	bool shutting_conns_down;
	bool terminating;
	bool killing;
};

extern RemoteSerializer* remote_serializer;

#endif
