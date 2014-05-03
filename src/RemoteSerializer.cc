// Processes involved in the communication:
//
//	 (Local-Parent) <-> (Local-Child) <-> (Remote-Child) <-> (Remote-Parent)
//
// Message types (for parent<->child communication the CMsg's peer indicates
// about whom we're talking).
//
// Communication protocol version
//	VERSION <version> <cache_size> <data-format-version>
//		<run-time> [<class:string>]
//
// Send serialization
//	SERIAL <serialization>
//
// Terminate(d) connection
//	CLOSE
//
// Close(d) all connections
//	CLOSE_ALL
//
// Connect to remote side
//	CONNECT_TO <id-of-new-peer> <ip> <port> <retry-interval> <use-ssl>
//
// Connected to remote side
//	CONNECTED <ip> <port>
//
// Request events from remote side
//	REQUEST_EVENTS <list of events>
//
// Request synchronization of IDs with remote side
//	REQUEST_SYNC <authorative:bool>
//
// Listen for connection on ip/port (ip may be INADDR_ANY)
//	LISTEN <ip> <port> <use_ssl>
//
// Close listen ports.
//	LISTEN_STOP
//
// Error caused by host
//	ERROR <msg>
//
// Some statistics about the given peer connection
//	STATS <string>
//
// Requests to set a new capture_filter
//	CAPTURE_FILTER <string>
//
// Ping to peer
//  PING <struct ping_args>
//
// Pong from peer
//  PONG <struct ping_args>
//
// Announce our capabilities
//  CAPS <flags> <reserved> <reserved>
//
// Activate compression (parent->child)
//  COMPRESS <level>
//
// Indicate that all following blocks are compressed (child->child)
//  COMPRESS
//
// Synchronize for pseudo-realtime processing.
// Signals that we have reached sync-point number <count>.
//  SYNC_POINT <count>
//
// Signals the child that we want to terminate. Anything sent after this may
// get lost. When the child answers with another TERMINATE it is safe to
// shutdown.
//  TERMINATE
//
// Debug-only: tell child to dump recently received/sent data to disk.
//  DEBUG_DUMP
//
// Valid messages between processes:
//
//	Main -> Child
//		CONNECT_TO
//		REQUEST_EVENTS
//		SERIAL
//		CLOSE
//		CLOSE_ALL
//		LISTEN
//		LISTEN_STOP
//		CAPTURE_FILTER
//		VERSION
//		REQUEST_SYNC
//		PHASE_DONE
//		PING
//		PONG
//		CAPS
//		COMPRESS
//		SYNC_POINT
//		DEBUG_DUMP
//		REMOTE_PRINT
//
//	Child -> Main
//		CONNECTED
//		REQUEST_EVENTS
//		SERIAL
//		CLOSE
//		ERROR
//		STATS
//		VERSION
//		CAPTURE_FILTER
//		REQUEST_SYNC
//		PHASE_DONE
//		PING
//		PONG
//		CAPS
//		LOG
//		SYNC_POINT
//		REMOTE_PRINT
//
//	Child <-> Child
//		VERSION
//		SERIAL
//		REQUEST_EVENTS
//		CAPTURE_FILTER
//		REQUEST_SYNC
//		PHASE_DONE
//		PING
//		PONG
//		CAPS
//		COMPRESS
//		SYNC_POINT
//		REMOTE_PRINT
//
//  A connection between two peers has four phases:
//
//  Setup:
//      Initial phase.
//      VERSION messages must be exchanged.
//      Ends when both peers have sent VERSION.
//  Handshake:
//      REQUEST_EVENTS/REQUEST_SYNC/CAPTURE_FILTER/CAPS/selected SERIALs
//      may be exchanged.
//      Phase ends when both peers have sent PHASE_DONE.
//  State synchronization:
//      Entered iff at least one of the peers has sent REQUEST_SYNC.
//      The peer with the smallest runtime (incl. in VERSION msg) sends
//      SERIAL messages compromising all of its state.
//      Phase ends when peer sends another PHASE_DONE.
//  Running:
//      Peers exchange SERIAL (and PING/PONG) messages.
//      Phase ends with connection tear-down by one of the peers.

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <strings.h>
#include <stdarg.h>

#include "config.h"
#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#include <sys/resource.h>

#include <algorithm>
#include <string>
#include <sstream>
#include <vector>

#include "RemoteSerializer.h"
#include "Func.h"
#include "EventRegistry.h"
#include "Event.h"
#include "Net.h"
#include "NetVar.h"
#include "Scope.h"
#include "Sessions.h"
#include "File.h"
#include "Conn.h"
#include "Reporter.h"
#include "threading/SerialTypes.h"
#include "logging/Manager.h"
#include "IPAddr.h"
#include "bro_inet_ntop.h"

extern "C" {
#include "setsignal.h"
};

// Gets incremented each time there's an incompatible change
// to the communication internals.
static const unsigned short PROTOCOL_VERSION = 0x07;

static const char MSG_NONE = 0x00;
static const char MSG_VERSION = 0x01;
static const char MSG_SERIAL = 0x02;
static const char MSG_CLOSE = 0x03;
static const char MSG_CLOSE_ALL = 0x04;
static const char MSG_ERROR = 0x05;
static const char MSG_CONNECT_TO = 0x06;
static const char MSG_CONNECTED = 0x07;
static const char MSG_REQUEST_EVENTS = 0x08;
static const char MSG_LISTEN = 0x09;
static const char MSG_LISTEN_STOP = 0x0a;
static const char MSG_STATS = 0x0b;
static const char MSG_CAPTURE_FILTER = 0x0c;
static const char MSG_REQUEST_SYNC = 0x0d;
static const char MSG_PHASE_DONE = 0x0e;
static const char MSG_PING = 0x0f;
static const char MSG_PONG = 0x10;
static const char MSG_CAPS = 0x11;
static const char MSG_COMPRESS = 0x12;
static const char MSG_LOG = 0x13;
static const char MSG_SYNC_POINT = 0x14;
static const char MSG_TERMINATE = 0x15;
static const char MSG_DEBUG_DUMP = 0x16;
static const char MSG_REMOTE_PRINT = 0x17;
static const char MSG_LOG_CREATE_WRITER = 0x18;
static const char MSG_LOG_WRITE = 0x19;
static const char MSG_REQUEST_LOGS = 0x20;

// Update this one whenever adding a new ID:
static const char MSG_ID_MAX = MSG_REQUEST_LOGS;

static const uint32 FINAL_SYNC_POINT = /* UINT32_MAX */ 4294967295U;

// Buffer size for remote-print data
static const int PRINT_BUFFER_SIZE = 10 * 1024;
static const int SOCKBUF_SIZE = 1024 * 1024;

// Buffer size for remote-log data.
static const int LOG_BUFFER_SIZE = 50 * 1024;

struct ping_args {
	uint32 seq;
	double time1; // Round-trip time parent1<->parent2
	double time2; // Round-trip time child1<->parent2
	double time3; // Round-trip time child2<->parent2
};

#ifdef DEBUG
# define DEBUG_COMM(msg) DBG_LOG(DBG_COMM, msg)
#else
# define DEBUG_COMM(msg)
#endif

#define READ_CHUNK(i, c, do_if_eof) \
	{ \
	if ( ! i->Read(&c) ) \
		{ \
		if ( i->Eof() ) \
			{ \
			do_if_eof; \
			} \
		else \
			Error(fmt("can't read data chunk: %s", io->Error()), i == io); \
		return false; \
		} \
	\
	if ( ! c ) \
		return true; \
	}

#define READ_CHUNK_FROM_CHILD(c) \
	{ \
	if ( ! io->Read(&c) ) \
		{ \
		if ( io->Eof() ) \
			ChildDied(); \
		else \
			Error(fmt("can't read data chunk: %s", io->Error())); \
		return false; \
		} \
	\
	if ( ! c ) \
		{ \
		idle = io->IsIdle();\
		return true; \
		} \
	idle = false; \
	}

static const char* msgToStr(int msg)
	{
# define MSG_STR(x) case x: return #x;
	switch ( msg ) {
	MSG_STR(MSG_VERSION)
	MSG_STR(MSG_NONE)
	MSG_STR(MSG_SERIAL)
	MSG_STR(MSG_CLOSE)
	MSG_STR(MSG_CLOSE_ALL)
	MSG_STR(MSG_ERROR)
	MSG_STR(MSG_CONNECT_TO)
	MSG_STR(MSG_CONNECTED)
	MSG_STR(MSG_REQUEST_EVENTS)
	MSG_STR(MSG_LISTEN)
	MSG_STR(MSG_LISTEN_STOP)
	MSG_STR(MSG_STATS)
	MSG_STR(MSG_CAPTURE_FILTER)
	MSG_STR(MSG_REQUEST_SYNC)
	MSG_STR(MSG_PHASE_DONE)
	MSG_STR(MSG_PING)
	MSG_STR(MSG_PONG)
	MSG_STR(MSG_CAPS)
	MSG_STR(MSG_COMPRESS)
	MSG_STR(MSG_LOG)
	MSG_STR(MSG_SYNC_POINT)
	MSG_STR(MSG_TERMINATE)
	MSG_STR(MSG_DEBUG_DUMP)
	MSG_STR(MSG_REMOTE_PRINT)
	MSG_STR(MSG_LOG_CREATE_WRITER)
	MSG_STR(MSG_LOG_WRITE)
	MSG_STR(MSG_REQUEST_LOGS)
	default:
		return "UNKNOWN_MSG";
	}
	}

static vector<string> tokenize(const string& s, char delim)
	{
	vector<string> tokens;
	stringstream ss(s);
	string token;

	while ( std::getline(ss, token, delim) )
		tokens.push_back(token);

	return tokens;
	}

// Start of every message between two processes. We do the low-level work
// ourselves to make this 64-bit safe. (The actual layout is an artifact of
// an earlier design that depended on how a 32-bit GCC lays out its structs ...)
class CMsg {
public:
	CMsg(char type, RemoteSerializer::PeerID peer)
		{
		buffer[0] = type;
		uint32 tmp = htonl(peer);
		memcpy(buffer + 4, &tmp, sizeof(tmp));
		}

	char Type()	{ return buffer[0]; }

	RemoteSerializer::PeerID Peer()
		{
		uint32 tmp;
		memcpy(&tmp, buffer + 4, sizeof(tmp));
		return ntohl(tmp);
		}

	const char* Raw()	{ return buffer; }

private:
	char buffer[8];
};

static bool sendCMsg(ChunkedIO* io, char msg_type, RemoteSerializer::PeerID id)
	{
	// We use the new[] operator here to avoid mismatches
	// when deleting the data.
	CMsg* msg = (CMsg*) new char[sizeof(CMsg)];
	new (msg) CMsg(msg_type, id);

	ChunkedIO::Chunk* c = new ChunkedIO::Chunk((char*)msg, sizeof(CMsg));
	return io->Write(c);
	}

static ChunkedIO::Chunk* makeSerialMsg(RemoteSerializer::PeerID id)
	{
	// We use the new[] operator here to avoid mismatches
	// when deleting the data.
	CMsg* msg = (CMsg*) new char[sizeof(CMsg)];
	new (msg) CMsg(MSG_SERIAL, id);

	ChunkedIO::Chunk* c = new ChunkedIO::Chunk((char*)msg, sizeof(CMsg));
	return c;
	}

inline void RemoteSerializer::SetupSerialInfo(SerialInfo* info, Peer* peer)
	{
	info->chunk = makeSerialMsg(peer->id);
	if ( peer->caps & Peer::NO_CACHING )
		info->cache = false;

	if ( ! (peer->caps & Peer::PID_64BIT) || peer->phase != Peer::RUNNING )
		info->pid_32bit = true;

	if ( (peer->caps & Peer::NEW_CACHE_STRATEGY) &&
	     peer->phase == Peer::RUNNING )
		info->new_cache_strategy = true;

	if ( (peer->caps & Peer::BROCCOLI_PEER) )
		info->broccoli_peer = true;

	info->include_locations = false;
	}

static bool sendToIO(ChunkedIO* io, ChunkedIO::Chunk* c)
	{
	if ( ! io->Write(c) )
		{
		reporter->Warning("can't send chunk: %s", io->Error());
		return false;
		}

	return true;
	}

static bool sendToIO(ChunkedIO* io, char msg_type, RemoteSerializer::PeerID id,
			const char* str, int len = -1, bool delete_with_free = false)
	{
	if ( ! sendCMsg(io, msg_type, id) )
		{
		reporter->Warning("can't send message of type %d: %s", msg_type, io->Error());
		return false;
		}

	uint32 sz = len >= 0 ? len : strlen(str) + 1;
	ChunkedIO::Chunk* c = new ChunkedIO::Chunk(const_cast<char*>(str), sz);

	if ( delete_with_free )
		c->free_func = ChunkedIO::Chunk::free_func_free;
	else
		c->free_func = ChunkedIO::Chunk::free_func_delete;

	return sendToIO(io, c);
	}

static bool sendToIO(ChunkedIO* io, char msg_type, RemoteSerializer::PeerID id,
			int nargs, va_list ap)
	{
	if ( ! sendCMsg(io, msg_type, id) )
		{
		reporter->Warning("can't send message of type %d: %s", msg_type, io->Error());
		return false;
		}

	if ( nargs == 0 )
		return true;

	uint32* args = new uint32[nargs];

	for ( int i = 0; i < nargs; i++ )
		args[i] = htonl(va_arg(ap, uint32));

	ChunkedIO::Chunk* c = new ChunkedIO::Chunk((char*)args,
	                                           sizeof(uint32) * nargs);
	return sendToIO(io, c);
	}

#ifdef DEBUG
static inline char* fmt_uint32s(int nargs, va_list ap)
	{
	static char buf[512];
	char* p = buf;
	*p = '\0';
	for ( int i = 0; i < nargs; i++ )
		p += snprintf(p, sizeof(buf) - (p - buf),
				" 0x%08x", va_arg(ap, uint32));
	buf[511] = '\0';
	return buf;
	}
#endif

static pid_t child_pid = 0;

// Return true if message type is sent by a peer (rather than the child
// process itself).
static inline bool is_peer_msg(int msg)
	{
	return msg == MSG_VERSION ||
		msg == MSG_SERIAL ||
		msg == MSG_REQUEST_EVENTS ||
		msg == MSG_REQUEST_SYNC ||
		msg == MSG_CAPTURE_FILTER ||
		msg == MSG_PHASE_DONE ||
		msg == MSG_PING ||
		msg == MSG_PONG ||
		msg == MSG_CAPS ||
		msg == MSG_COMPRESS ||
		msg == MSG_SYNC_POINT ||
		msg == MSG_REMOTE_PRINT ||
		msg == MSG_LOG_CREATE_WRITER ||
		msg == MSG_LOG_WRITE ||
		msg == MSG_REQUEST_LOGS;
	}

bool RemoteSerializer::IsConnectedPeer(PeerID id)
	{
	if ( id == PEER_NONE )
		return true;

	return LookupPeer(id, true) != 0;
	}

class IncrementalSendTimer : public Timer {
public:
	IncrementalSendTimer(double t, RemoteSerializer::Peer* p, SerialInfo* i)
		: Timer(t, TIMER_INCREMENTAL_SEND), info(i), peer(p)	{}
	virtual void Dispatch(double t, int is_expire)
		{
		// Never suspend when we're finishing up.
		if ( terminating )
			info->may_suspend = false;

		remote_serializer->SendAllSynchronized(peer, info);
		}

	SerialInfo* info;
	RemoteSerializer::Peer* peer;
};

RemoteSerializer::RemoteSerializer()
	{
	initialized = false;
	current_peer = 0;
	msgstate = TYPE;
	id_counter = 1;
	listening = false;
	ignore_accesses = false;
	propagate_accesses = 1;
	current_sync_point = 0;
	syncing_times = false;
	io = 0;
	closed = false;
	terminating = false;
	in_sync = 0;
	last_flush = 0;
	received_logs = 0;
	current_id = 0;
	current_msgtype = 0;
	current_args = 0;
	source_peer = 0;
	}

RemoteSerializer::~RemoteSerializer()
	{
	if ( child_pid )
		{
		if ( kill(child_pid, SIGKILL) < 0 )
			reporter->Warning("warning: cannot kill child (pid %d), %s", child_pid, strerror(errno));

		else if ( waitpid(child_pid, 0, 0) < 0 )
			reporter->Warning("warning: error encountered during waitpid(%d), %s", child_pid, strerror(errno));
		}

	delete io;
	}

void RemoteSerializer::Init()
	{
	if ( initialized )
		return;

	if ( reading_traces && ! pseudo_realtime )
		{
		using_communication = 0;
		return;
		}

	Fork();

	io_sources.Register(this);

	Log(LogInfo, fmt("communication started, parent pid is %d, child pid is %d", getpid(), child_pid));
	initialized = 1;
	}

void RemoteSerializer::SetSocketBufferSize(int fd, int opt, const char *what, int size, int verbose)
	{
	int defsize = 0;
	socklen_t len = sizeof(defsize);

	if ( getsockopt(fd, SOL_SOCKET, opt, (void *)&defsize, &len) < 0 )
		{
		if ( verbose )
			Log(LogInfo, fmt("warning: cannot get socket buffer size (%s): %s", what, strerror(errno)));
		return;
		}

	for ( int trysize = size; trysize > defsize; trysize -= 1024 )
		{
		if ( setsockopt(fd, SOL_SOCKET, opt, &trysize, sizeof(trysize)) >= 0 )
			{
			if ( verbose )
			    {
			    if ( trysize == size )
				    Log(LogInfo, fmt("raised pipe's socket buffer size from %dK to %dK", defsize / 1024, trysize / 1024));
			    else
				    Log(LogInfo, fmt("raised pipe's socket buffer size from %dK to %dK (%dK was requested)", defsize / 1024, trysize / 1024, size / 1024));
			    }
			return;
			}
		}

	Log(LogInfo, fmt("warning: cannot increase %s socket buffer size from %dK (%dK was requested)", what, defsize / 1024, size / 1024));
	}

void RemoteSerializer::Fork()
	{
	if ( child_pid )
		return;

	// If we are re-forking, remove old entries
	loop_over_list(peers, i)
		RemovePeer(peers[i]);

	// Create pipe for communication between parent and child.
	int pipe[2];

	if ( socketpair(AF_UNIX, SOCK_STREAM, 0, pipe) < 0 )
		{
		Error(fmt("can't create pipe: %s", strerror(errno)));
		return;
		}

	// Try to increase the size of the socket send and receive buffers.
	SetSocketBufferSize(pipe[0], SO_SNDBUF, "SO_SNDBUF", SOCKBUF_SIZE, 1);
	SetSocketBufferSize(pipe[0], SO_RCVBUF, "SO_RCVBUF", SOCKBUF_SIZE, 0);
	SetSocketBufferSize(pipe[1], SO_SNDBUF, "SO_SNDBUF", SOCKBUF_SIZE, 0);
	SetSocketBufferSize(pipe[1], SO_RCVBUF, "SO_RCVBUF", SOCKBUF_SIZE, 0);

	child_pid = 0;

	int pid = fork();

	if ( pid < 0 )
		{
		Error(fmt("can't fork: %s", strerror(errno)));
		return;
		}

	if ( pid > 0 )
		{
		// Parent
		child_pid = pid;

		io = new ChunkedIOFd(pipe[0], "parent->child", child_pid);
		if ( ! io->Init() )
			{
			Error(fmt("can't init child io: %s", io->Error()));
			exit(1); // FIXME: Better way to handle this?
			}

		safe_close(pipe[1]);

		return;
		}
	else
		{ // child
		SocketComm child;

		ChunkedIOFd* io =
			new ChunkedIOFd(pipe[1], "child->parent", getppid());
		if ( ! io->Init() )
			{
			Error(fmt("can't init parent io: %s", io->Error()));
			exit(1);
			}

		child.SetParentIO(io);
		safe_close(pipe[0]);

		// Close file descriptors.
		safe_close(0);
		safe_close(1);
		safe_close(2);

		// Be nice.
		setpriority(PRIO_PROCESS, 0, 5);

		child.Run();
		reporter->InternalError("cannot be reached");
		}
	}

RemoteSerializer::PeerID RemoteSerializer::Connect(const IPAddr& ip,
		const string& zone_id, uint16 port, const char* our_class, double retry,
		bool use_ssl)
	{
	if ( ! using_communication )
		return true;

	if ( ! initialized )
		reporter->InternalError("remote serializer not initialized");

	if ( ! child_pid )
		Fork();

	Peer* p = AddPeer(ip, port);
	p->orig = true;

	if ( our_class )
		p->our_class = our_class;

	const size_t BUFSIZE = 1024;
	char* data = new char[BUFSIZE];
	snprintf(data, BUFSIZE,
	         "%"PRI_PTR_COMPAT_UINT",%s,%s,%"PRIu16",%"PRIu32",%d", p->id,
	         ip.AsString().c_str(), zone_id.c_str(), port, uint32(retry),
	         use_ssl);

	if ( ! SendToChild(MSG_CONNECT_TO, p, data) )
		{
		RemovePeer(p);
		return false;
		}

	p->state = Peer::PENDING;
	return p->id;
	}

bool RemoteSerializer::CloseConnection(PeerID id)
	{
	if ( ! using_communication )
		return true;

	Peer* peer = LookupPeer(id, true);
	if ( ! peer )
		{
		reporter->Error("unknown peer id %d for closing connection", int(id));
		return false;
		}

	return CloseConnection(peer);
	}

bool RemoteSerializer::CloseConnection(Peer* peer)
	{
	if ( peer->suspended_processing )
		{
		net_continue_processing();
		peer->suspended_processing = false;
		}

	if ( peer->state == Peer::CLOSING )
		return true;

	FlushPrintBuffer(peer);
	FlushLogBuffer(peer);

	Log(LogInfo, "closing connection", peer);

	peer->state = Peer::CLOSING;
	return SendToChild(MSG_CLOSE, peer, 0);
	}

bool RemoteSerializer::RequestSync(PeerID id, bool auth)
	{
	if ( ! using_communication )
		return true;

	Peer* peer = LookupPeer(id, true);
	if ( ! peer )
		{
		reporter->Error("unknown peer id %d for request sync", int(id));
		return false;
		}

	if ( peer->phase != Peer::HANDSHAKE )
		{
		reporter->Error("can't request sync from peer; wrong phase %d",
				peer->phase);
		return false;
		}

	if ( ! SendToChild(MSG_REQUEST_SYNC, peer, 1, auth ? 1 : 0) )
		return false;

	peer->sync_requested |= Peer::WE | (auth ? Peer::AUTH_WE : 0);

	return true;
	}

bool RemoteSerializer::RequestLogs(PeerID id)
	{
	if ( ! using_communication )
		return true;

	Peer* peer = LookupPeer(id, true);
	if ( ! peer )
		{
		reporter->Error("unknown peer id %d for request logs", int(id));
		return false;
		}

	if ( peer->phase != Peer::HANDSHAKE )
		{
		reporter->Error("can't request logs from peer; wrong phase %d",
			     peer->phase);
		return false;
		}

	if ( ! SendToChild(MSG_REQUEST_LOGS, peer, 0) )
		return false;

	return true;
	}

bool RemoteSerializer::RequestEvents(PeerID id, RE_Matcher* pattern)
	{
	if ( ! using_communication )
		return true;

	Peer* peer = LookupPeer(id, true);
	if ( ! peer )
		{
		reporter->Error("unknown peer id %d for request sync", int(id));
		return false;
		}

	if ( peer->phase != Peer::HANDSHAKE )
		{
		reporter->Error("can't request events from peer; wrong phase %d",
				peer->phase);
		return false;
		}

	EventRegistry::string_list* handlers = event_registry->Match(pattern);

	// Concat the handlers' names.
	int len = 0;
	loop_over_list(*handlers, i)
		len += strlen((*handlers)[i]) + 1;

	if ( ! len )
		{
		Log(LogInfo, "warning: no events to request");
		delete handlers;
		return true;
		}

	char* data = new char[len];
	char* d = data;
	loop_over_list(*handlers, j)
		{
		for ( const char* p = (*handlers)[j]; *p; *d++ = *p++ )
			;
		*d++ = '\0';
		}

	delete handlers;

	return SendToChild(MSG_REQUEST_EVENTS, peer, data, len);
	}

bool RemoteSerializer::SetAcceptState(PeerID id, bool accept)
	{
	Peer* p = LookupPeer(id, false);
	if ( ! p )
		return true;

	p->accept_state = accept;
	return true;
	}

bool RemoteSerializer::SetCompressionLevel(PeerID id, int level)
	{
	Peer* p = LookupPeer(id, false);
	if ( ! p )
		return true;

	p->comp_level = level;
	return true;
	}

bool RemoteSerializer::CompleteHandshake(PeerID id)
	{
	Peer* p = LookupPeer(id, false);
	if ( ! p )
		return true;

	if ( p->phase != Peer::HANDSHAKE )
		{
		reporter->Error("can't complete handshake; wrong phase %d",
				p->phase);
		return false;
		}

	p->handshake_done |= Peer::WE;

	if ( ! SendToChild(MSG_PHASE_DONE, p, 0) )
		return false;

	if ( p->handshake_done == Peer::BOTH )
		HandshakeDone(p);

	return true;
	}

bool RemoteSerializer::SendCall(SerialInfo* info, PeerID id,
					const char* name, val_list* vl)
	{
	if ( ! using_communication || terminating )
		return true;

	Peer* peer = LookupPeer(id, true);
	if ( ! peer )
		return false;

	return SendCall(info, peer, name, vl);
	}

bool RemoteSerializer::SendCall(SerialInfo* info, Peer* peer,
					const char* name, val_list* vl)
	{
	if ( peer->phase != Peer::RUNNING || terminating )
		return false;

	++stats.events.out;
	SetCache(peer->cache_out);
	SetupSerialInfo(info, peer);

	if ( ! Serialize(info, name, vl) )
		{
		FatalError(io->Error());
		return false;
		}

	return true;
	}

bool RemoteSerializer::SendCall(SerialInfo* info, const char* name,
				val_list* vl)
	{
	if ( ! IsOpen() || ! PropagateAccesses() || terminating )
		return true;

	loop_over_list(peers, i)
		{
		// Do not send event back to originating peer.
		if ( peers[i] == current_peer )
			continue;

		SerialInfo new_info(*info);
		if ( ! SendCall(&new_info, peers[i], name, vl) )
			return false;
		}

	return true;
	}

bool RemoteSerializer::SendAccess(SerialInfo* info, Peer* peer,
					const StateAccess& access)
	{
	if ( ! (peer->sync_requested & Peer::PEER) || terminating )
		return true;

#ifdef DEBUG
	ODesc desc;
	access.Describe(&desc);
	DBG_LOG(DBG_COMM, "Sending %s", desc.Description());
#endif

	++stats.accesses.out;
	SetCache(peer->cache_out);
	SetupSerialInfo(info, peer);
	info->globals_as_names = true;

	if ( ! Serialize(info, access) )
		{
		FatalError(io->Error());
		return false;
		}

	return true;
	}

bool RemoteSerializer::SendAccess(SerialInfo* info, PeerID pid,
					const StateAccess& access)
	{
	Peer* p = LookupPeer(pid, false);
	if ( ! p )
		return true;

	return SendAccess(info, p, access);
	}

bool RemoteSerializer::SendAccess(SerialInfo* info, const StateAccess& access)
	{
	if ( ! IsOpen() || ! PropagateAccesses() || terminating )
		return true;

	// A real broadcast would be nice here. But the different peers have
	// different serialization caches, so we cannot simply send the same
	// serialization to all of them ...
	loop_over_list(peers, i)
		{
		// Do not send access back to originating peer.
		if ( peers[i] == source_peer )
			continue;

		// Only sent accesses for fully setup peers.
		if ( peers[i]->phase != Peer::RUNNING )
			continue;

		SerialInfo new_info(*info);
		if ( ! SendAccess(&new_info, peers[i], access) )
			return false;
		}

	return true;
	}

bool RemoteSerializer::SendAllSynchronized(Peer* peer, SerialInfo* info)
	{
	// FIXME: When suspending ID serialization works, remove!
	DisableSuspend suspend(info);

	current_peer = peer;

	Continuation* cont = &info->cont;
	ptr_compat_int index;

	if ( info->cont.NewInstance() )
		{
		Log(LogInfo, "starting to send full state", peer);
		index = 0;
		}

	else
		{
		index = int(ptr_compat_int(cont->RestoreState()));
		if ( ! cont->ChildSuspended() )
			cont->Resume();
		}

	for ( ; index < sync_ids.length(); ++index )
		{
		if ( ! sync_ids[index]->ID_Val() )
			{
#ifdef DEBUG
			DBG_LOG(DBG_COMM, "Skip sync of ID with null value: %s\n",
			        sync_ids[index]->Name());
#endif
			continue;
			}
		cont->SaveContext();

		StateAccess sa(OP_ASSIGN, sync_ids[index],
				sync_ids[index]->ID_Val());
		// FIXME: When suspending ID serialization works, we need to
		//  addsupport to StateAccesses, too.
		bool result = SendAccess(info, peer, sa);
		cont->RestoreContext();

		if ( ! result )
			return false;

		if ( cont->ChildSuspended() || info->may_suspend )
			{
			double t = network_time + state_write_delay;
			timer_mgr->Add(new IncrementalSendTimer(t, peer, info));

			cont->SaveState((void*) index);
			if ( info->may_suspend )
				cont->Suspend();

			return true;
			}
		}

	if ( ! SendToChild(MSG_PHASE_DONE, peer, 0) )
		return false;

	suspend.Release();
	delete info;

	Log(LogInfo, "done sending full state", peer);

	return EnterPhaseRunning(peer);
	}

bool RemoteSerializer::SendID(SerialInfo* info, Peer* peer, const ID& id)
	{
	if ( terminating )
		return true;

	// FIXME: When suspending ID serialization works, remove!
	DisableSuspend suspend(info);

	if ( info->cont.NewInstance() )
		++stats.ids.out;

	SetCache(peer->cache_out);
	SetupSerialInfo(info, peer);
	info->cont.SaveContext();
	bool result = Serialize(info, id);
	info->cont.RestoreContext();

	if ( ! result )
		{
		FatalError(io->Error());
		return false;
		}

	return true;
	}

bool RemoteSerializer::SendID(SerialInfo* info, PeerID pid, const ID& id)
	{
	if ( ! using_communication || terminating )
		return true;

	Peer* peer = LookupPeer(pid, true);
	if ( ! peer )
		return false;

	if ( peer->phase != Peer::RUNNING )
		return false;

	return SendID(info, peer, id);
	}

bool RemoteSerializer::SendConnection(SerialInfo* info, PeerID id,
					const Connection& c)
	{
	if ( ! using_communication || terminating )
		return true;

	Peer* peer = LookupPeer(id, true);
	if ( ! peer )
		return false;

	if ( peer->phase != Peer::RUNNING )
		return false;

	++stats.conns.out;
	SetCache(peer->cache_out);
	SetupSerialInfo(info, peer);

	if ( ! Serialize(info, c) )
				{
		FatalError(io->Error());
		return false;
		}

	return true;
	}

bool RemoteSerializer::SendCaptureFilter(PeerID id, const char* filter)
	{
	if ( ! using_communication || terminating )
		return true;

	Peer* peer = LookupPeer(id, true);
	if ( ! peer )
		return false;

	if ( peer->phase != Peer::HANDSHAKE )
		{
		reporter->Error("can't sent capture filter to peer; wrong phase %d", peer->phase);
		return false;
		}

	return SendToChild(MSG_CAPTURE_FILTER, peer, copy_string(filter));
	}

bool RemoteSerializer::SendPacket(SerialInfo* info, const Packet& p)
	{
	if ( ! IsOpen() || !PropagateAccesses() || terminating )
		return true;

	loop_over_list(peers, i)
		{
		// Only sent packet for fully setup peers.
		if ( peers[i]->phase != Peer::RUNNING )
			continue;

		SerialInfo new_info(*info);
		if ( ! SendPacket(&new_info, peers[i], p) )
			return false;
		}

	return true;
	}

bool RemoteSerializer::SendPacket(SerialInfo* info, PeerID id, const Packet& p)
	{
	if ( ! using_communication || terminating )
		return true;

	Peer* peer = LookupPeer(id, true);
	if ( ! peer )
		return false;

	return SendPacket(info, peer, p);
	}

bool RemoteSerializer::SendPacket(SerialInfo* info, Peer* peer, const Packet& p)
	{
	++stats.packets.out;
	SetCache(peer->cache_out);
	SetupSerialInfo(info, peer);

	if ( ! Serialize(info, p) )
		{
		FatalError(io->Error());
		return false;
		}

	return true;
	}

bool RemoteSerializer::SendPing(PeerID id, uint32 seq)
	{
	if ( ! using_communication || terminating )
		return true;

	Peer* peer = LookupPeer(id, true);
	if ( ! peer )
		return false;

	char* data = new char[sizeof(ping_args)];

	ping_args* args = (ping_args*) data;
	args->seq = htonl(seq);
	args->time1 = htond(current_time(true));
	args->time2 = 0;
	args->time3 = 0;

	return SendToChild(MSG_PING, peer, data, sizeof(ping_args));
	}

bool RemoteSerializer::SendCapabilities(Peer* peer)
	{
	if ( peer->phase != Peer::HANDSHAKE )
		{
		reporter->Error("can't sent capabilties to peer; wrong phase %d",
				peer->phase);
		return false;
		}

	uint32 caps = 0;

	caps |= Peer::COMPRESSION;
	caps |= Peer::PID_64BIT;
	caps |= Peer::NEW_CACHE_STRATEGY;

	return SendToChild(MSG_CAPS, peer, 3, caps, 0, 0);
	}

bool RemoteSerializer::Listen(const IPAddr& ip, uint16 port, bool expect_ssl,
                              bool ipv6, const string& zone_id, double retry)
	{
	if ( ! using_communication )
		return true;

	if ( ! initialized )
		reporter->InternalError("remote serializer not initialized");

	if ( ! ipv6 && ip.GetFamily() == IPv6 &&
	     ip != IPAddr("0.0.0.0") && ip != IPAddr("::") )
		reporter->FatalError("Attempt to listen on address %s, but IPv6 "
		                     "communication disabled", ip.AsString().c_str());

	const size_t BUFSIZE = 1024;
	char* data = new char[BUFSIZE];
	snprintf(data, BUFSIZE, "%s,%"PRIu16",%d,%d,%s,%"PRIu32,
	         ip.AsString().c_str(), port, expect_ssl, ipv6, zone_id.c_str(),
	         (uint32) retry);

	if ( ! SendToChild(MSG_LISTEN, 0, data) )
		return false;

	listening = true;
	closed = false;
	return true;
	}

void RemoteSerializer::SendSyncPoint(uint32 point)
	{
	if ( ! (remote_trace_sync_interval && pseudo_realtime) || terminating )
		return;

	current_sync_point = point;

	loop_over_list(peers, i)
		if ( peers[i]->phase == Peer::RUNNING &&
		     ! SendToChild(MSG_SYNC_POINT, peers[i],
					1, current_sync_point) )
			return;

	if ( ! syncing_times )
		{
		Log(LogInfo, "waiting for peers");
		syncing_times = true;

		loop_over_list(peers, i)
			{
			// Need to do this once per peer to correctly
			// track the number of suspend calls.
			net_suspend_processing();
			peers[i]->suspended_processing = true;
			}
		}

	CheckSyncPoints();
	}

uint32 RemoteSerializer::SendSyncPoint()
	{
	Log(LogInfo, fmt("reached sync-point %u", current_sync_point));
	SendSyncPoint(current_sync_point + 1);
	return current_sync_point;
	}

void RemoteSerializer::SendFinalSyncPoint()
	{
	Log(LogInfo, fmt("reached end of trace, sending final sync point"));
	SendSyncPoint(FINAL_SYNC_POINT);
	}

bool RemoteSerializer::Terminate()
	{
	loop_over_list(peers, i)
	    {
	    FlushPrintBuffer(peers[i]);
	    FlushLogBuffer(peers[i]);
	    }

	Log(LogInfo, fmt("terminating..."));

	return terminating = SendToChild(MSG_TERMINATE, 0, 0);
	}

bool RemoteSerializer::StopListening()
	{
	if ( ! listening )
		return true;

	if ( ! SendToChild(MSG_LISTEN_STOP, 0, 0) )
		return false;

	listening = false;
	closed = ! IsActive();
	return true;
	}

void RemoteSerializer::Register(ID* id)
	{
	DBG_LOG(DBG_STATE, "&synchronized %s", id->Name());
	Unregister(id);
	Ref(id);
	sync_ids.append(id);
	}

void RemoteSerializer::Unregister(ID* id)
	{
	loop_over_list(sync_ids, i)
		if ( streq(sync_ids[i]->Name(), id->Name()) )
			{
			Unref(sync_ids[i]);
			sync_ids.remove_nth(i);
			break;
			}
	}

void RemoteSerializer::GetFds(int* read, int* write, int* except)
	{
	*read = io->Fd();

	if ( io->CanWrite() )
		*write = io->Fd();
	}

double RemoteSerializer::NextTimestamp(double* local_network_time)
	{
	Poll(false);

	if ( received_logs > 0 )
		{
		// If we processed logs last time, assume there's more.
		idle = false;
		received_logs = 0;
		return timer_mgr->Time();
		}

	double et = events.length() ? events[0]->time : -1;
	double pt = packets.length() ? packets[0]->time : -1;

	if ( ! et )
		et = timer_mgr->Time();

	if ( ! pt )
		pt = timer_mgr->Time();

	if ( packets.length() )
		idle = false;

	if ( et >= 0 && (et < pt || pt < 0) )
		return et;

	if ( pt >= 0 )
		{
		// Return packet time as network time.
		*local_network_time = packets[0]->p->time;
		return pt;
		}

	return -1;
	}

TimerMgr::Tag* RemoteSerializer::GetCurrentTag()
	{
	return packets.length() ? &packets[0]->p->tag : 0;
	}

void RemoteSerializer::Process()
	{
	Poll(false);

	int i = 0;
	while ( events.length() )
		{
		if ( max_remote_events_processed &&
		     ++i > max_remote_events_processed )
			break;

		BufferedEvent* be = events[0];
		::Event* event = new ::Event(be->handler, be->args, be->src);

		Peer* old_current_peer = current_peer;
		// Prevent the source peer from getting the event back.
		current_peer = LookupPeer(be->src, true); // may be null.
		mgr.Dispatch(event, ! forward_remote_events);
		current_peer = old_current_peer;

		assert(events[0] == be);
		delete be;
		events.remove_nth(0);
		}

	// We shouldn't pass along more than one packet, as otherwise the
	// timer mgr will not advance.
	if ( packets.length() )
		{
		BufferedPacket* bp = packets[0];
		Packet* p = bp->p;

		// FIXME: The following chunk of code is copied from
		// net_packet_dispatch().  We should change that function
		// to accept an IOSource instead of the PktSrc.
		network_time = p->time;

		SegmentProfiler(segment_logger, "expiring-timers");
		TimerMgr* tmgr = sessions->LookupTimerMgr(GetCurrentTag());
		current_dispatched =
			tmgr->Advance(network_time, max_timer_expires);

		current_hdr = p->hdr;
		current_pkt = p->pkt;
		current_pktsrc = 0;
		current_iosrc = this;
		sessions->NextPacket(p->time, p->hdr, p->pkt, p->hdr_size);
		mgr.Drain();

		current_hdr = 0;	// done with these
		current_pkt = 0;
		current_iosrc = 0;

		delete p;
		delete bp;
		packets.remove_nth(0);
		}

	if ( packets.length() )
		idle = false;
	}

void RemoteSerializer::Finish()
	{
	if ( ! using_communication )
		return;

	do
		Poll(true);
	while ( io->CanWrite() );

	loop_over_list(peers, i)
		{
		CloseConnection(peers[i]);
		}
	}

bool RemoteSerializer::Poll(bool may_block)
	{
	if ( ! child_pid )
		return true;

	// See if there's any peer waiting for initial state synchronization.
	if ( sync_pending.length() && ! in_sync )
		{
		Peer* p = sync_pending[0];
		sync_pending.remove_nth(0);
		HandshakeDone(p);
		}

	io->Flush();
	idle = false;

	switch ( msgstate ) {
	case TYPE:
		{
		current_peer = 0;
		current_msgtype = MSG_NONE;

		// CMsg follows
		ChunkedIO::Chunk* c;
		READ_CHUNK_FROM_CHILD(c);

		CMsg* msg = (CMsg*) c->data;
		current_peer = LookupPeer(msg->Peer(), false);
		current_id = msg->Peer();
		current_msgtype = msg->Type();
		current_args = 0;

		delete c;

		switch ( current_msgtype ) {
		case MSG_CLOSE:
		case MSG_CLOSE_ALL:
		case MSG_LISTEN_STOP:
		case MSG_PHASE_DONE:
		case MSG_TERMINATE:
		case MSG_DEBUG_DUMP:
		case MSG_REQUEST_LOGS:
			{
			// No further argument chunk.
			msgstate = TYPE;
			return DoMessage();
			}
		case MSG_VERSION:
		case MSG_SERIAL:
		case MSG_ERROR:
		case MSG_CONNECT_TO:
		case MSG_CONNECTED:
		case MSG_REQUEST_EVENTS:
		case MSG_REQUEST_SYNC:
		case MSG_LISTEN:
		case MSG_STATS:
		case MSG_CAPTURE_FILTER:
		case MSG_PING:
		case MSG_PONG:
		case MSG_CAPS:
		case MSG_COMPRESS:
		case MSG_LOG:
		case MSG_SYNC_POINT:
		case MSG_REMOTE_PRINT:
		case MSG_LOG_CREATE_WRITER:
		case MSG_LOG_WRITE:
			{
			// One further argument chunk.
			msgstate = ARGS;
			return Poll(may_block);
			}

		case MSG_NONE:
			InternalCommError(fmt("unexpected msg type %d",
						current_msgtype));
			return true;

		default:
			InternalCommError(fmt("unknown msg type %d in Poll()",
						current_msgtype));
			return true;
		}
		}

	case ARGS:
		{
		// Argument chunk follows.
		ChunkedIO::Chunk* c;
		READ_CHUNK_FROM_CHILD(c);

		current_args = c;
		msgstate = TYPE;
		bool result = DoMessage();

		delete current_args;
		current_args = 0;

		return result;
		}

	default:
		reporter->InternalError("unknown msgstate");
	}

	reporter->InternalError("cannot be reached");
	return false;
	}

bool RemoteSerializer::DoMessage()
	{
	if ( current_peer &&
	     (current_peer->state == Peer::CLOSING ||
	      current_peer->state == Peer::CLOSED) &&
	     is_peer_msg(current_msgtype) )
		{
		// We shut the connection to this peer down,
		// so we ignore all further messages.
		DEBUG_COMM(fmt("parent: ignoring %s due to shutdown of peer #%" PRI_SOURCE_ID,
					msgToStr(current_msgtype),
					current_peer ? current_peer->id : 0));
		return true;
		}

	DEBUG_COMM(fmt("parent: %s from child; peer is #%" PRI_SOURCE_ID,
			msgToStr(current_msgtype),
			current_peer ? current_peer->id : 0));

	if ( current_peer &&
	     (current_msgtype < 0 || current_msgtype > MSG_ID_MAX) )
		{
		Log(LogError, "garbage message from peer, shutting down",
			current_peer);
		CloseConnection(current_peer);
		return true;
		}

	// As long as we haven't finished the version
	// handshake, no other messages than MSG_VERSION
	// are allowed from peer.
	if ( current_peer && current_peer->phase == Peer::SETUP &&
	     is_peer_msg(current_msgtype) && current_msgtype != MSG_VERSION )
		{
		Log(LogError, "peer did not send version", current_peer);
		CloseConnection(current_peer);
		return true;
		}

	switch ( current_msgtype ) {
	case MSG_CLOSE:
		PeerDisconnected(current_peer);
		return true;

	case MSG_CONNECTED:
		return ProcessConnected();

	case MSG_SERIAL:
		return ProcessSerialization();

	case MSG_REQUEST_EVENTS:
		return ProcessRequestEventsMsg();

	case MSG_REQUEST_SYNC:
		return ProcessRequestSyncMsg();

	case MSG_PHASE_DONE:
		return ProcessPhaseDone();

	case MSG_ERROR:
		return ProcessLogMsg(true);

	case MSG_LOG:
		return ProcessLogMsg(false);

	case MSG_STATS:
		return ProcessStatsMsg();

	case MSG_CAPTURE_FILTER:
		return ProcessCaptureFilterMsg();

	case MSG_VERSION:
		return ProcessVersionMsg();

	case MSG_PING:
		return ProcessPingMsg();

	case MSG_PONG:
		return ProcessPongMsg();

	case MSG_CAPS:
		return ProcessCapsMsg();

	case MSG_SYNC_POINT:
		return ProcessSyncPointMsg();

	case MSG_TERMINATE:
		assert(terminating);
		io_sources.Terminate();
		return true;

	case MSG_REMOTE_PRINT:
		return ProcessRemotePrint();

	case MSG_LOG_CREATE_WRITER:
		return ProcessLogCreateWriter();

	case MSG_LOG_WRITE:
		return ProcessLogWrite();

	case MSG_REQUEST_LOGS:
		return ProcessRequestLogs();

	default:
		DEBUG_COMM(fmt("unexpected msg type: %d",
					int(current_msgtype)));
		InternalCommError(fmt("unexpected msg type in DoMessage(): %d",
					int(current_msgtype)));
		return true; // keep going
	}

	reporter->InternalError("cannot be reached");
	return false;
	}

void RemoteSerializer::PeerDisconnected(Peer* peer)
	{
	assert(peer);

	if ( peer->suspended_processing )
		{
		net_continue_processing();
		peer->suspended_processing = false;
		}

	if ( peer->state == Peer::CLOSED || peer->state == Peer::INIT )
		return;

	if ( peer->state == Peer::PENDING )
		{
		peer->state = Peer::CLOSED;
		Log(LogError, "could not connect", peer);
		return;
		}

	Log(LogInfo, "peer disconnected", peer);

	if ( peer->phase != Peer::SETUP )
		RaiseEvent(remote_connection_closed, peer);

	if ( in_sync == peer )
		in_sync = 0;

	peer->state = Peer::CLOSED;
	peer->phase = Peer::UNKNOWN;
	peer->cache_in->Clear();
	peer->cache_out->Clear();
	UnregisterHandlers(peer);
	}

void RemoteSerializer::PeerConnected(Peer* peer)
	{
	if ( peer->state == Peer::CONNECTED )
		return;

	peer->state = Peer::CONNECTED;
	peer->phase = Peer::SETUP;
	peer->sent_version = Peer::NONE;
	peer->sync_requested = Peer::NONE;
	peer->handshake_done = Peer::NONE;

	peer->cache_in->Clear();
	peer->cache_out->Clear();
	peer->our_runtime = int(current_time(true) - bro_start_time);
	peer->sync_point = 0;
	peer->logs_requested = false;

	if ( ! SendCMsgToChild(MSG_VERSION, peer) )
		return;

	int len = 4 * sizeof(uint32) + peer->our_class.size() + 1;
	char* data = new char[len];
	uint32* args = (uint32*) data;

	*args++ = htonl(PROTOCOL_VERSION);
	*args++ = htonl(peer->cache_out->GetMaxCacheSize());
	*args++ = htonl(DATA_FORMAT_VERSION);
	*args++ = htonl(peer->our_runtime);
	strcpy((char*) args, peer->our_class.c_str());

	ChunkedIO::Chunk* c = new ChunkedIO::Chunk(data, len);

	if ( peer->our_class.size() )
		Log(LogInfo, fmt("sending class \"%s\"", peer->our_class.c_str()), peer);

	if ( ! SendToChild(c) )
		{
		Log(LogError, "can't send version message");
		CloseConnection(peer);
		return;
		}

	peer->sent_version |= Peer::WE;
	Log(LogInfo, "peer connected", peer);
	Log(LogInfo, "phase: version", peer);
	}

RecordVal* RemoteSerializer::MakePeerVal(Peer* peer)
	{
	RecordVal* v = new RecordVal(::peer);
	v->Assign(0, new Val(uint32(peer->id), TYPE_COUNT));
	// Sic! Network order for AddrVal, host order for PortVal.
	v->Assign(1, new AddrVal(peer->ip));
	v->Assign(2, new PortVal(peer->port, TRANSPORT_TCP));
	v->Assign(3, new Val(false, TYPE_BOOL));
	v->Assign(4, new StringVal(""));	// set when received
	v->Assign(5, peer->peer_class.size() ?
			new StringVal(peer->peer_class.c_str()) : 0);
	return v;
	}

RemoteSerializer::Peer* RemoteSerializer::AddPeer(const IPAddr& ip, uint16 port,
                                                  PeerID id)
	{
	Peer* peer = new Peer;
	peer->id = id != PEER_NONE ? id : id_counter++;
	peer->ip = ip;
	peer->port = port;
	peer->state = Peer::INIT;
	peer->phase = Peer::UNKNOWN;
	peer->sent_version = Peer::NONE;
	peer->sync_requested = Peer::NONE;
	peer->handshake_done = Peer::NONE;
	peer->orig = false;
	peer->accept_state = false;
	peer->send_state = false;
	peer->logs_requested = false;
	peer->caps = 0;
	peer->comp_level = 0;
	peer->suspended_processing = false;
	peer->caps = 0;
	peer->val = MakePeerVal(peer);
	peer->cache_in = new SerializationCache(MAX_CACHE_SIZE);
	peer->cache_out = new SerializationCache(MAX_CACHE_SIZE);
	peer->sync_point = 0;
	peer->print_buffer = 0;
	peer->print_buffer_used = 0;
	peer->log_buffer = new char[LOG_BUFFER_SIZE];
	peer->log_buffer_used = 0;

	peers.append(peer);
	Log(LogInfo, "added peer", peer);

	return peer;
	}

void RemoteSerializer::UnregisterHandlers(Peer* peer)
	{
	// Unregister the peers for the EventHandlers.
	loop_over_list(peer->handlers, i)
		{
		peer->handlers[i]->RemoveRemoteHandler(peer->id);
		}
	}

void RemoteSerializer::RemovePeer(Peer* peer)
	{
	if ( peer->suspended_processing )
		{
		net_continue_processing();
		peer->suspended_processing = false;
		}

	peers.remove(peer);
	UnregisterHandlers(peer);

	Log(LogInfo, "removed peer", peer);

	int id = peer->id;
	Unref(peer->val);
	delete [] peer->print_buffer;
	delete [] peer->log_buffer;
	delete peer->cache_in;
	delete peer->cache_out;
	delete peer;

	closed = ! IsActive();

	if ( in_sync == peer )
		in_sync = 0;
	}

RemoteSerializer::Peer* RemoteSerializer::LookupPeer(PeerID id,
							bool only_if_connected)
	{
	Peer* peer = 0;
	loop_over_list(peers, i)
		if ( peers[i]->id == id )
			{
			peer = peers[i];
			break;
			}

	if ( ! only_if_connected || (peer && peer->state == Peer::CONNECTED) )
		return peer;
	else
		return 0;
	}

bool RemoteSerializer::ProcessVersionMsg()
	{
	uint32* args = (uint32*) current_args->data;
	uint32 version = ntohl(args[0]);
	uint32 data_version = ntohl(args[2]);

	if ( PROTOCOL_VERSION != version )
		{
		Log(LogError, fmt("remote protocol version mismatch: got %d, but expected %d",
				version, PROTOCOL_VERSION), current_peer);
		CloseConnection(current_peer);
		return true;
		}

	// For backwards compatibility, data_version may be null.
	if ( data_version && DATA_FORMAT_VERSION != data_version )
		{
		Log(LogError, fmt("remote data version mismatch: got %d, but expected %d",
				data_version, DATA_FORMAT_VERSION),
				current_peer);
		CloseConnection(current_peer);
		return true;
		}

	uint32 cache_size = ntohl(args[1]);
	current_peer->cache_in->SetMaxCacheSize(cache_size);
	current_peer->runtime = ntohl(args[3]);

	current_peer->sent_version |= Peer::PEER;

	if ( current_args->len > 4 * sizeof(uint32) )
		{
		// The peer sends us a class string.
		const char* pclass = (const char*) &args[4];
		current_peer->peer_class = pclass;
		if ( *pclass )
			Log(LogInfo, fmt("peer sent class \"%s\"", pclass), current_peer);
		if ( current_peer->val )
			current_peer->val->Assign(5, new StringVal(pclass));
		}

	assert(current_peer->sent_version == Peer::BOTH);
	current_peer->phase = Peer::HANDSHAKE;
	Log(LogInfo, "phase: handshake", current_peer);

	if ( ! SendCapabilities(current_peer) )
		return false;

	RaiseEvent(remote_connection_established, current_peer);

	return true;
	}

bool RemoteSerializer::EnterPhaseRunning(Peer* peer)
	{
	if ( in_sync == peer )
		in_sync = 0;

	peer->phase = Peer::RUNNING;
	Log(LogInfo, "phase: running", peer);
	RaiseEvent(remote_connection_handshake_done, peer);

	if ( remote_trace_sync_interval )
		{
		loop_over_list(peers, i)
			{
			if ( ! SendToChild(MSG_SYNC_POINT, peers[i],
						1, current_sync_point) )
				return false;
			}
		}

	return true;
	}

bool RemoteSerializer::ProcessConnected()
	{
	// IP and port follow.
	vector<string> args = tokenize(current_args->data, ',');

	if ( args.size() != 2 )
		{
		InternalCommError("ProcessConnected() bad number of arguments");
		return false;
		}

	IPAddr host = IPAddr(args[0]);
	uint16 port;

	if ( ! atoi_n(args[1].size(), args[1].c_str(), 0, 10, port) )
		{
		InternalCommError("ProcessConnected() bad peer port string");
		return false;
		}

	if ( ! current_peer )
		{
		// The other side connected to one of our listening ports.
		current_peer = AddPeer(host, port, current_id);
		current_peer->orig = false;
		}
	else if ( current_peer->orig )
		{
		// It's a successful retry.
		current_peer->port = port;
		current_peer->accept_state = false;
		Unref(current_peer->val);
		current_peer->val = MakePeerVal(current_peer);
		}

	PeerConnected(current_peer);

	ID* descr = global_scope()->Lookup("peer_description");
	if ( ! descr )
		reporter->InternalError("peer_description not defined");

	SerialInfo info(this);
	SendID(&info, current_peer, *descr);

	return true;
	}

bool RemoteSerializer::ProcessRequestEventsMsg()
	{
	if ( ! current_peer )
		return false;

	// Register new handlers.
	char* p = current_args->data;
	while ( p < current_args->data + current_args->len )
		{
		EventHandler* handler = event_registry->Lookup(p);
		if ( handler )
			{
			handler->AddRemoteHandler(current_peer->id);
			current_peer->handlers.append(handler);
			RaiseEvent(remote_event_registered, current_peer, p);
			Log(LogInfo, fmt("registered for event %s", p),
					current_peer);

			// If the other side requested the print_hook event,
			// we initialize the buffer.
			if ( current_peer->print_buffer == 0 &&
			     streq(p, "print_hook") )
				{
				current_peer->print_buffer =
					new char[PRINT_BUFFER_SIZE];
				current_peer->print_buffer_used = 0;
				Log(LogInfo, "initialized print buffer",
					current_peer);
				}
			}
		else
			Log(LogInfo, fmt("request for unknown event %s", p),
					current_peer);

		p += strlen(p) + 1;
		}

	return true;
	}

bool RemoteSerializer::ProcessRequestSyncMsg()
	{
	if ( ! current_peer )
		return false;

	int auth = 0;
	uint32* args = (uint32*) current_args->data;
	if ( ntohl(args[0]) != 0 )
		{
		Log(LogInfo, "peer considers its state authoritative", current_peer);
		auth = Peer::AUTH_PEER;
		}

	current_peer->sync_requested |= Peer::PEER | auth;
	return true;
	}

bool RemoteSerializer::ProcessRequestLogs()
	{
	if ( ! current_peer )
		return false;

	Log(LogInfo, "peer requested logs", current_peer);

	current_peer->logs_requested = true;
	return true;
	}

bool RemoteSerializer::ProcessPhaseDone()
	{
	switch ( current_peer->phase ) {
	case Peer::HANDSHAKE:
		{
		current_peer->handshake_done |= Peer::PEER;

		if ( current_peer->handshake_done == Peer::BOTH )
			HandshakeDone(current_peer);
		break;
		}

	case Peer::SYNC:
		{
		// Make sure that the other side is supposed to sent us this.
		if ( current_peer->send_state )
			{
			Log(LogError, "unexpected phase_done in sync phase from peer", current_peer);
			CloseConnection(current_peer);
			return false;
			}

		if ( ! EnterPhaseRunning(current_peer) )
			{
			if ( current_peer->suspended_processing )
				{
				net_continue_processing();
				current_peer->suspended_processing = false;
				}

			return false;
			}

		if ( current_peer->suspended_processing )
			{
			net_continue_processing();
			current_peer->suspended_processing = false;
			}

		break;
		}

	default:
		Log(LogError, "unexpected phase_done", current_peer);
	    CloseConnection(current_peer);
	}

	return true;
	}

bool RemoteSerializer::HandshakeDone(Peer* peer)
	{
	if ( peer->caps & Peer::COMPRESSION && peer->comp_level > 0 )
		if ( ! SendToChild(MSG_COMPRESS, peer, 1, peer->comp_level) )
			return false;

	if ( ! (peer->caps & Peer::PID_64BIT) )
		Log(LogInfo, "peer does not support 64bit PIDs; using compatibility mode", peer);

	if ( (peer->caps & Peer::NEW_CACHE_STRATEGY) )
		Log(LogInfo, "peer supports keep-in-cache; using that", peer);

	if ( (peer->caps & Peer::BROCCOLI_PEER) )
		Log(LogInfo, "peer is a Broccoli", peer);

	if ( peer->logs_requested )
		log_mgr->SendAllWritersTo(peer->id);

	if ( peer->sync_requested != Peer::NONE )
		{
		if ( in_sync )
			{
			Log(LogInfo, "another sync in progress, waiting...",
					peer);
			sync_pending.append(peer);
			return true;
			}

		if ( (peer->sync_requested & Peer::AUTH_PEER) &&
		     (peer->sync_requested & Peer::AUTH_WE) )
			{
			Log(LogError, "misconfiguration: authoritative state on both sides",
				current_peer);
			CloseConnection(peer);
			return false;
			}

		in_sync = peer;
		peer->phase = Peer::SYNC;

		// If only one side has requested state synchronization,
		// it will get all the state from the peer.
		//
		// If both sides have shown interest, the one considering
		// itself authoritative will send the state.  If none is
		// authoritative, the peer which is running longest sends
		// its state.
		//
		if ( (peer->sync_requested & Peer::BOTH) != Peer::BOTH )
			{
			// One side.
			if ( peer->sync_requested & Peer::PEER )
				peer->send_state = true;
			else if ( peer->sync_requested & Peer::WE )
				peer->send_state = false;
			else
				reporter->InternalError("illegal sync_requested value");
			}
		else
			{
			// Both.
			if ( peer->sync_requested & Peer::AUTH_WE )
				peer->send_state = true;
			else if ( peer->sync_requested & Peer::AUTH_PEER )
				peer->send_state = false;
			else
				{
				if ( peer->our_runtime == peer->runtime )
					peer->send_state = peer->orig;
				else
					peer->send_state = (peer->our_runtime >
								peer->runtime);
				}
			}

		Log(LogInfo, fmt("phase: sync (%s)", (peer->send_state ? "sender" : "receiver")), peer);

		if ( peer->send_state )
			{
			SerialInfo* info = new SerialInfo(this);
			SendAllSynchronized(peer, info);
			}

		else
			{
			// Suspend until we got everything.
			net_suspend_processing();
			peer->suspended_processing = true;
			}
		}
	else
		return EnterPhaseRunning(peer);

	return true;
	}

bool RemoteSerializer::ProcessPingMsg()
	{
	if ( ! current_peer )
		return false;

	if ( ! SendToChild(MSG_PONG, current_peer,
				current_args->data, current_args->len) )
		return false;

	return true;
	}

bool RemoteSerializer::ProcessPongMsg()
	{
	if ( ! current_peer )
		return false;

	ping_args* args = (ping_args*) current_args->data;

	val_list* vl = new val_list;
	vl->append(current_peer->val->Ref());
	vl->append(new Val((unsigned int) ntohl(args->seq), TYPE_COUNT));
	vl->append(new Val(current_time(true) - ntohd(args->time1),
				TYPE_INTERVAL));
	vl->append(new Val(ntohd(args->time2), TYPE_INTERVAL));
	vl->append(new Val(ntohd(args->time3), TYPE_INTERVAL));
	mgr.QueueEvent(remote_pong, vl);
	return true;
	}

bool RemoteSerializer::ProcessCapsMsg()
	{
	if ( ! current_peer )
		return false;

	uint32* args = (uint32*) current_args->data;
	current_peer->caps = ntohl(args[0]);
	return true;
	}

bool RemoteSerializer::ProcessLogMsg(bool is_error)
	{
	Log(is_error ? LogError : LogInfo, current_args->data, 0, LogChild);
	return true;
	}

bool RemoteSerializer::ProcessStatsMsg()
	{
	// Take the opportunity to log our stats, too.
	LogStats();

	// Split the concatenated child stats into indiviual log messages.
	int count = 0;
	for ( char* p = current_args->data;
	      p < current_args->data + current_args->len; p += strlen(p) + 1 )
		Log(LogInfo, fmt("child statistics: [%d] %s", count++, p),
				current_peer);

	return true;
	}

bool RemoteSerializer::ProcessCaptureFilterMsg()
	{
	if ( ! current_peer )
		return false;

	RaiseEvent(remote_capture_filter, current_peer, current_args->data);
	return true;
	}

bool RemoteSerializer::CheckSyncPoints()
	{
	if ( ! current_sync_point )
		return false;

	int ready = 0;

	loop_over_list(peers, i)
		if ( peers[i]->sync_point >= current_sync_point )
			ready++;

	if ( ready < remote_trace_sync_peers )
		return false;

	if ( current_sync_point == FINAL_SYNC_POINT )
		{
		Log(LogInfo, fmt("all peers reached final sync-point, going to finish"));
		Terminate();
		}
	else
		Log(LogInfo, fmt("all peers reached sync-point %u",
					current_sync_point));

	if ( syncing_times )
		{
		loop_over_list(peers, i)
			{
			if ( peers[i]->suspended_processing )
				{
				net_continue_processing();
				peers[i]->suspended_processing = false;
				}
			}

		syncing_times = false;
		}

	return true;
	}

bool RemoteSerializer::ProcessSyncPointMsg()
	{
	if ( ! current_peer )
		return false;

	uint32* args = (uint32*) current_args->data;
	uint32 count = ntohl(args[0]);

	current_peer->sync_point = max(current_peer->sync_point, count);

	if ( current_peer->sync_point == FINAL_SYNC_POINT )
		Log(LogInfo, fmt("reached final sync-point"), current_peer);
	else
		Log(LogInfo, fmt("reached sync-point %u", current_peer->sync_point), current_peer);

	if ( syncing_times )
		CheckSyncPoints();

	return true;
	}

bool RemoteSerializer::ProcessSerialization()
	{
	if ( current_peer->state == Peer::CLOSING )
		return false;

	SetCache(current_peer->cache_in);
	UnserialInfo info(this);

	bool accept_state = current_peer->accept_state;

#if 0
	// If processing is suspended, we unserialize the data but throw
	// it away.
	if ( current_peer->phase == Peer::RUNNING &&
	     net_is_processing_suspended() )
		 accept_state = false;
#endif

	assert(current_args);
	info.chunk = current_args;

	info.install_globals = accept_state;
	info.install_conns = accept_state;
	info.ignore_callbacks = ! accept_state;

	if ( current_peer->phase != Peer::RUNNING )
		info.id_policy = UnserialInfo::InstantiateNew;
	else
		info.id_policy = accept_state ?
					UnserialInfo::CopyNewToCurrent :
					UnserialInfo::Keep;

	if ( ! (current_peer->caps & Peer::PID_64BIT) ||
	     current_peer->phase != Peer::RUNNING )
		info.pid_32bit = true;

	if ( (current_peer->caps & Peer::NEW_CACHE_STRATEGY) &&
	     current_peer->phase == Peer::RUNNING )
		info.new_cache_strategy = true;

	if ( current_peer->caps & Peer::BROCCOLI_PEER )
		info.broccoli_peer = true;

	if ( ! forward_remote_state_changes )
		ignore_accesses = true;

	source_peer = current_peer;
	int i = Unserialize(&info);
	source_peer = 0;

	if ( ! forward_remote_state_changes )
		ignore_accesses = false;

	if ( i < 0 )
		{
		Log(LogError, "unserialization error", current_peer);
		CloseConnection(current_peer);
		// Error
		return false;
		}

	return true;
	}

bool RemoteSerializer::FlushPrintBuffer(Peer* p)
	{
	if ( p->state == Peer::CLOSING )
		return false;

	if ( ! (p->print_buffer && p->print_buffer_used) )
		return true;

	SendToChild(MSG_REMOTE_PRINT, p, p->print_buffer, p->print_buffer_used);

	p->print_buffer = new char[PRINT_BUFFER_SIZE];
	p->print_buffer_used = 0;
	return true;
	}

bool RemoteSerializer::SendPrintHookEvent(BroFile* f, const char* txt, size_t len)
	{
	loop_over_list(peers, i)
		{
		Peer* p = peers[i];

		if ( ! p->print_buffer )
			continue;

		const char* fname = f->Name();
		if ( ! fname )
			continue; // not a managed file.

		// We cut off everything after the max buffer size.  That
		// makes the code a bit easier, and we shouldn't have such
		// long lines anyway.
		len = min<size_t>(len, PRINT_BUFFER_SIZE - strlen(fname) - 2);

		// If there's not enough space in the buffer, flush it.

		int need = strlen(fname) + 1 + len + 1;
		if ( p->print_buffer_used + need > PRINT_BUFFER_SIZE )
			{
			if ( ! FlushPrintBuffer(p) )
				return false;
			}

		assert(p->print_buffer_used + need <= PRINT_BUFFER_SIZE);

		char* dst = p->print_buffer + p->print_buffer_used;
		strcpy(dst, fname);
		dst += strlen(fname) + 1;
		memcpy(dst, txt, len);
		dst += len;
		*dst++ = '\0';

		p->print_buffer_used = dst - p->print_buffer;
		}

	return true;
	}

bool RemoteSerializer::ProcessRemotePrint()
	{
	if ( current_peer->state == Peer::CLOSING )
		return false;

	const char* p = current_args->data;
	while ( p < current_args->data + current_args->len )
		{
		const char* fname = p;
		p += strlen(p) + 1;
		const char* txt = p;
		p += strlen(p) + 1;

		val_list* vl = new val_list(2);
		BroFile* f = BroFile::GetFile(fname);
		Ref(f);
		vl->append(new Val(f));
		vl->append(new StringVal(txt));
		GotEvent("print_hook", -1.0, print_hook, vl);
		}

	return true;
	}

bool RemoteSerializer::SendLogCreateWriter(EnumVal* id, EnumVal* writer, const logging::WriterBackend::WriterInfo& info, int num_fields, const threading::Field* const * fields)
	{
	loop_over_list(peers, i)
		{
		SendLogCreateWriter(peers[i]->id, id, writer, info, num_fields, fields);
		}

	return true;
	}

bool RemoteSerializer::SendLogCreateWriter(PeerID peer_id, EnumVal* id, EnumVal* writer, const logging::WriterBackend::WriterInfo& info, int num_fields, const threading::Field* const * fields)
	{
	SetErrorDescr("logging");

	ChunkedIO::Chunk* c = 0;

	Peer* peer = LookupPeer(peer_id, true);
	if ( ! peer )
		return false;

	if ( peer->phase != Peer::HANDSHAKE && peer->phase != Peer::RUNNING )
		return false;

	if ( ! peer->logs_requested )
		return false;

	BinarySerializationFormat fmt;

	fmt.StartWrite();

	bool success = fmt.Write(id->AsEnum(), "id") &&
		fmt.Write(writer->AsEnum(), "writer") &&
		fmt.Write(num_fields, "num_fields") &&
		info.Write(&fmt);

	if ( ! success )
		goto error;

	for ( int i = 0; i < num_fields; i++ )
		{
		if ( ! fields[i]->Write(&fmt) )
			goto error;
		}

	if ( ! SendToChild(MSG_LOG_CREATE_WRITER, peer, 0) )
		goto error;

	c = new ChunkedIO::Chunk;
	c->len = fmt.EndWrite(&c->data);
	c->free_func = ChunkedIO::Chunk::free_func_free;

	if ( ! SendToChild(c) )
		goto error;

	return true;

error:
	delete c;

	FatalError(io->Error());
	return false;
	}

bool RemoteSerializer::SendLogWrite(EnumVal* id, EnumVal* writer, string path, int num_fields, const threading::Value* const * vals)
	{
	loop_over_list(peers, i)
		{
		SendLogWrite(peers[i], id, writer, path, num_fields, vals);
		}

	return true;
	}

bool RemoteSerializer::SendLogWrite(Peer* peer, EnumVal* id, EnumVal* writer, string path, int num_fields, const threading::Value* const * vals)
	{
	if ( peer->phase != Peer::HANDSHAKE && peer->phase != Peer::RUNNING )
		return false;

	if ( ! peer->logs_requested )
		return false;

	if ( ! peer->log_buffer )
		// Peer shutting down.
		return false;

	// Serialize the log record entry.

	BinarySerializationFormat fmt;

	fmt.StartWrite();

	bool success = fmt.Write(id->AsEnum(), "id") &&
		fmt.Write(writer->AsEnum(), "writer") &&
		fmt.Write(path, "path") &&
		fmt.Write(num_fields, "num_fields");

	if ( ! success )
		goto error;

	for ( int i = 0; i < num_fields; i++ )
		{
		if ( ! vals[i]->Write(&fmt) )
			goto error;
		}

	// Ok, we have the binary data now.
	char* data;
	int len;

	len = fmt.EndWrite(&data);

	assert(len > 10);

	// Do we have not enough space in the buffer, or was the last flush a
	// while ago? If so, flush first.
	if ( len > (LOG_BUFFER_SIZE - peer->log_buffer_used) || (network_time - last_flush > 1.0) )
		{
		if ( ! FlushLogBuffer(peer) )
			{
			free(data);
			return false;
			}
		}

	// If the data is actually larger than our complete buffer, just send it out.
	if ( len > LOG_BUFFER_SIZE )
		return SendToChild(MSG_LOG_WRITE, peer, data, len, true);

	// Now we have space in the buffer, copy it into there.
	memcpy(peer->log_buffer + peer->log_buffer_used, data, len);
	peer->log_buffer_used += len;
	assert(peer->log_buffer_used <= LOG_BUFFER_SIZE);

	free(data);

	return true;

error:
	FatalError(io->Error());
	return false;
	}

bool RemoteSerializer::FlushLogBuffer(Peer* p)
	{
	if ( ! p->logs_requested )
		return false;

	last_flush = network_time;

	if ( p->state == Peer::CLOSING )
		return false;

	if ( ! (p->log_buffer && p->log_buffer_used) )
		return true;

	char* data = new char[p->log_buffer_used];
	memcpy(data, p->log_buffer, p->log_buffer_used);
	SendToChild(MSG_LOG_WRITE, p, data, p->log_buffer_used);

	p->log_buffer_used = 0;
	return true;
	}

bool RemoteSerializer::ProcessLogCreateWriter()
	{
	if ( current_peer->state == Peer::CLOSING )
		return false;

#ifdef USE_PERFTOOLS_DEBUG
	// Don't track allocations here, they'll be released only after the
	// main loop exists. And it's just a tiny amount anyway.
	HeapLeakChecker::Disabler disabler;
#endif

	assert(current_args);

	EnumVal* id_val = 0;
	EnumVal* writer_val = 0;
	threading::Field** fields = 0;
	int delete_fields_up_to = -1;

	BinarySerializationFormat fmt;
	fmt.StartRead(current_args->data, current_args->len);

	int id, writer;
	int num_fields;
	logging::WriterBackend::WriterInfo* info = new logging::WriterBackend::WriterInfo();

	bool success = fmt.Read(&id, "id") &&
		fmt.Read(&writer, "writer") &&
		fmt.Read(&num_fields, "num_fields") &&
		info->Read(&fmt);

	if ( ! success )
		goto error;

	fields = new threading::Field* [num_fields];

	for ( int i = 0; i < num_fields; i++ )
		{
		fields[i] = new threading::Field;
		if ( ! fields[i]->Read(&fmt) )
			{
			delete_fields_up_to = i + 1;
			goto error;
			}
		}

	fmt.EndRead();

	id_val = new EnumVal(id, BifType::Enum::Log::ID);
	writer_val = new EnumVal(writer, BifType::Enum::Log::Writer);

	if ( ! log_mgr->CreateWriter(id_val, writer_val, info, num_fields, fields,
	                             true, false, true) )
		{
		delete_fields_up_to = num_fields;
		goto error;
		}

	Unref(id_val);
	Unref(writer_val);

	return true;

error:
	Unref(id_val);
	Unref(writer_val);
	delete info;

	for ( int i = 0; i < delete_fields_up_to; ++i )
		delete fields[i];

	delete [] fields;
	Error("write error for creating writer");
	return false;
	}

bool RemoteSerializer::ProcessLogWrite()
	{
	if ( current_peer->state == Peer::CLOSING )
		return false;

	assert(current_args);

	BinarySerializationFormat fmt;
	fmt.StartRead(current_args->data, current_args->len);

	while ( fmt.BytesRead() != (int)current_args->len )
		{
		// Unserialize one entry.
		EnumVal* id_val = 0;
		EnumVal* writer_val = 0;
		threading::Value** vals = 0;

		int id, writer;
		string path;
		int num_fields;

		bool success = fmt.Read(&id, "id") &&
			fmt.Read(&writer, "writer") &&
			fmt.Read(&path, "path") &&
			fmt.Read(&num_fields, "num_fields");

		if ( ! success )
			goto error;

		vals = new threading::Value* [num_fields];

		for ( int i = 0; i < num_fields; i++ )
			{
			vals[i] = new threading::Value;

			if ( ! vals[i]->Read(&fmt) )
				{
				for ( int j = 0; j <= i; ++j )
					delete vals[j];

				delete [] vals;
				goto error;
				}
			}

		id_val = new EnumVal(id, BifType::Enum::Log::ID);
		writer_val = new EnumVal(writer, BifType::Enum::Log::Writer);

		success = log_mgr->Write(id_val, writer_val, path, num_fields, vals);

		Unref(id_val);
		Unref(writer_val);

		if ( ! success )
			goto error;

		}

	fmt.EndRead();

	++received_logs;

	return true;

error:
	Error("write error for log entry");
	return false;
	}

void RemoteSerializer::GotEvent(const char* name, double time,
				EventHandlerPtr event, val_list* args)
	{
	if ( time >= 0 )
		{
		// Marker for being called from ProcessRemotePrint().
		DEBUG_COMM("parent: got event");
		++stats.events.in;
		}

	if ( ! current_peer )
		{
		Error("unserialized event from unknown peer");
		return;
		}

	BufferedEvent* e = new BufferedEvent;

	// Our time, not the time when the event was generated.
	e->time = pkt_srcs.length() ?
			time_t(network_time) : time_t(timer_mgr->Time());

	e->src = current_peer->id;
	e->handler = event;
	e->args = args;

	// If needed, coerce received record arguments to the expected record type.
	if ( e->handler->FType() )
		{
		const type_list* arg_types = e->handler->FType()->ArgTypes()->Types();
		loop_over_list(*args, i)
			{
			Val* v = (*args)[i];
			BroType* v_t = v->Type();
			BroType* arg_t = (*arg_types)[i];
			if ( v_t->Tag() == TYPE_RECORD && arg_t->Tag() == TYPE_RECORD )
				{
				if ( ! same_type(v_t, arg_t) )
					{
					Val* nv = v->AsRecordVal()->CoerceTo(arg_t->AsRecordType());
					if ( nv )
						{
						args->replace(i, nv);
						Unref(v);
						}
					}
				}
			}
		}

	events.append(e);
	}

void RemoteSerializer::GotFunctionCall(const char* name, double time,
					Func* function, val_list* args)
	{
	DEBUG_COMM("parent: got function call");
	++stats.events.in;

	if ( ! current_peer )
		{
		Error("unserialized function from unknown peer");
		return;
		}

	try
		{
		function->Call(args);
		}

	catch ( InterpreterException& e )
		{ /* Already reported. */ }
	}

void RemoteSerializer::GotID(ID* id, Val* val)
	{
	++stats.ids.in;

	if ( ! current_peer )
		{
		Error("unserialized id from unknown peer");
		Unref(id);
		return;
		}

	if ( current_peer->phase == Peer::HANDSHAKE &&
	     streq(id->Name(), "peer_description") )
		{
		if ( val->Type()->Tag() != TYPE_STRING )
			{
			Error("peer_description not a string");
			Unref(id);
			return;
			}

		const char* desc = val->AsString()->CheckString();
		current_peer->val->Assign(4, new StringVal(desc));

		Log(LogInfo, fmt("peer_description is %s", *desc ? desc : "not set"),
			current_peer);

		Unref(id);
		return;
		}

	if ( id->Name()[0] == '#' )
		{
		// This is a globally unique, non-user-visible ID.

		// Only MutableVals can be bound to names starting with '#'.
		assert(val->IsMutableVal());

		// It must be already installed in the global namespace:
		// either we saw it before, or MutableVal::Unserialize()
		// installed it.
		assert(global_scope()->Lookup(id->Name()));

		// Only synchronized values can arrive here.
		assert(((MutableVal*) val)->GetProperties() & MutableVal::SYNCHRONIZED);

		DBG_LOG(DBG_COMM, "got ID %s from peer\n", id->Name());
		}

	Unref(id);
	}

void RemoteSerializer::GotConnection(Connection* c)
	{
	++stats.conns.in;

	// Nothing else to-do.  Connection will be installed automatically
	// (if allowed).

	Unref(c);
	}

void RemoteSerializer::GotStateAccess(StateAccess* s)
	{
	++stats.accesses.in;

	ODesc d;
	DBG_LOG(DBG_COMM, "got StateAccess: %s", (s->Describe(&d), d.Description()));

	if ( ! current_peer )
		{
		Error("unserialized function from unknown peer");
		return;
		}

	if ( current_peer->sync_requested & Peer::WE )
		s->Replay();

	delete s;
	}

void RemoteSerializer::GotTimer(Timer* s)
	{
	reporter->Error("RemoteSerializer::GotTimer not implemented");
	}

void RemoteSerializer::GotPacket(Packet* p)
	{
	++stats.packets.in;

	BufferedPacket* bp = new BufferedPacket;
	bp->time = time_t(timer_mgr->Time());
	bp->p = p;
	packets.append(bp);
	}

void RemoteSerializer::Log(LogLevel level, const char* msg)
	{
	Log(level, msg, 0, LogParent);
	}

void RemoteSerializer::Log(LogLevel level, const char* msg, Peer* peer,
				LogSrc src)
	{
	if ( peer )
		{
		val_list* vl = new val_list();
		vl->append(peer->val->Ref());
		vl->append(new Val(level, TYPE_COUNT));
		vl->append(new Val(src, TYPE_COUNT));
		vl->append(new StringVal(msg));
		mgr.QueueEvent(remote_log_peer, vl);
		}
	else
		{
		val_list* vl = new val_list();
		vl->append(new Val(level, TYPE_COUNT));
		vl->append(new Val(src, TYPE_COUNT));
		vl->append(new StringVal(msg));
		mgr.QueueEvent(remote_log, vl);
		}

#ifdef DEBUG
	const int BUFSIZE = 1024;
	char buffer[BUFSIZE];
	int len = 0;

	if ( peer )
		len += snprintf(buffer + len, sizeof(buffer) - len, "[#%d/%s:%d] ",
		                int(peer->id), peer->ip.AsURIString().c_str(),
		                peer->port);

	len += safe_snprintf(buffer + len, sizeof(buffer) - len, "%s", msg);

	DEBUG_COMM(fmt("parent: %.6f %s", current_time(), buffer));
#endif
	}

void RemoteSerializer::RaiseEvent(EventHandlerPtr event, Peer* peer,
					const char* arg)
	{
	val_list* vl = new val_list;

	if ( peer )
		{
		Ref(peer->val);
		vl->append(peer->val);
		}
	else
		{
		Val* v = mgr.GetLocalPeerVal();
		v->Ref();
		vl->append(v);
		}

	if ( arg )
		vl->append(new StringVal(arg));

	// If we only have remote sources, the network time
	// will not increase as long as no peers are connected.
	// Therefore, we send these events immediately.
	mgr.Dispatch(new Event(event, vl, PEER_LOCAL));
	}

void RemoteSerializer::LogStats()
	{
	if ( ! io )
		return;

	char buffer[512];
	io->Stats(buffer, 512);
	Log(LogInfo, fmt("parent statistics: %s events=%lu/%lu operations=%lu/%lu",
		buffer, stats.events.in, stats.events.out,
		stats.accesses.in, stats.accesses.out));
	}

RecordVal* RemoteSerializer::GetPeerVal(PeerID id)
	{
	Peer* peer = LookupPeer(id, true);
	if ( ! peer )
		return 0;

	Ref(peer->val);
	return peer->val;
	}

void RemoteSerializer::ChildDied()
	{
	Log(LogError, "child died");
	closed = true;
	child_pid = 0;

	// Shut down the main process as well.
	terminate_processing();
	}

bool RemoteSerializer::SendCMsgToChild(char msg_type, Peer* peer)
	{
	if ( ! sendCMsg(io, msg_type, peer ? peer->id : PEER_NONE) )
		{
		reporter->Warning("can't send message of type %d: %s",
				msg_type, io->Error());
		return false;
		}
	return true;
	}

bool RemoteSerializer::SendToChild(char type, Peer* peer, char* str, int len,
                                   bool delete_with_free)
	{
	DEBUG_COMM(fmt("parent: (->child) %s (#%" PRI_SOURCE_ID ", %s)", msgToStr(type), peer ? peer->id : PEER_NONE, str));

	if ( child_pid && sendToIO(io, type, peer ? peer->id : PEER_NONE, str, len,
	                           delete_with_free) )
		return true;

	if ( delete_with_free )
		free(str);
	else
		delete [] str;

	if ( ! child_pid )
		return false;

	if ( io->Eof() )
		ChildDied();

	FatalError(io->Error());
	return false;
	}

bool RemoteSerializer::SendToChild(char type, Peer* peer, int nargs, ...)
	{
	va_list ap;

#ifdef DEBUG
	va_start(ap, nargs);
	DEBUG_COMM(fmt("parent: (->child) %s (#%" PRI_SOURCE_ID ",%s)",
			msgToStr(type), peer ? peer->id : PEER_NONE, fmt_uint32s(nargs, ap)));
	va_end(ap);
#endif

	if ( child_pid )
		{
		va_start(ap, nargs);
		bool ret = sendToIO(io, type, peer ? peer->id : PEER_NONE, nargs, ap);
		va_end(ap);

		if ( ret )
			return true;
		}

	if ( ! child_pid )
		return false;

	if ( io->Eof() )
		ChildDied();

	FatalError(io->Error());
	return false;
	}

bool RemoteSerializer::SendToChild(ChunkedIO::Chunk* c)
	{
	DEBUG_COMM(fmt("parent: (->child) chunk of size %d", c->len));

	if ( child_pid && sendToIO(io, c) )
		return true;

	c->free_func(c->data);
	c->data = 0;

	if ( ! child_pid )
		return false;

	if ( io->Eof() )
		ChildDied();

	FatalError(io->Error());
	return false;
	}

void RemoteSerializer::FatalError(const char* msg)
	{
	msg = fmt("fatal error, shutting down communication: %s", msg);
	Log(LogError, msg);
	reporter->Error("%s", msg);

	closed = true;

	if ( kill(child_pid, SIGQUIT) < 0 )
		reporter->Warning("warning: cannot kill child pid %d, %s", child_pid, strerror(errno));

	child_pid = 0;
	using_communication = false;
	io->Clear();

	loop_over_list(peers, i)
		{
		// Make perftools happy.
		Peer* p = peers[i];
		delete [] p->log_buffer;
		delete [] p->print_buffer;
		p->log_buffer = p->print_buffer = 0;
		}
	}

bool RemoteSerializer::IsActive()
	{
	if ( listening )
		return true;

	loop_over_list(peers, i)
		if ( peers[i]->state == Peer::PENDING ||
		     peers[i]->state == Peer::CONNECTED )
			return true;

	return false;
	}

void RemoteSerializer::ReportError(const char* msg)
	{
	if ( current_peer && current_peer->phase != Peer::SETUP )
		RaiseEvent(remote_connection_error, current_peer, msg);
	Log(LogError, msg, current_peer);
	}

void RemoteSerializer::InternalCommError(const char* msg)
	{
#ifdef DEBUG_COMMUNICATION
	DumpDebugData();
#else
	reporter->InternalError("%s", msg);
#endif
	}

#ifdef DEBUG_COMMUNICATION

void RemoteSerializer::DumpDebugData()
	{
	Log(LogError, "dumping debug data and terminating ...");
	io->DumpDebugData("comm-dump.parent", true);
	io->DumpDebugData("comm-dump.parent", false);
	SendToChild(MSG_DEBUG_DUMP, 0, 0);
	Terminate();
	}

static ChunkedIO* openDump(const char* file)
	{
	int fd = open(file, O_RDONLY, 0600);

	if ( fd < 0 )
		{
		reporter->Error("cannot open %s: %s\n", file, strerror(errno));
		return 0;
		}

	return new ChunkedIOFd(fd, "dump-file");
	}

void RemoteSerializer::ReadDumpAsMessageType(const char* file)
	{
	ChunkedIO* io = openDump(file);
	if ( ! io )
		return;

	ChunkedIO::Chunk* chunk;

	if ( ! io->Read(&chunk, true ) )
		{
		reporter->Error("cannot read %s: %s\n", file, strerror(errno));
		return;
		}

	CMsg* msg = (CMsg*) chunk->data;

	delete [] chunk->data;
	delete io;
	}

void RemoteSerializer::ReadDumpAsSerialization(const char* file)
	{
	FileSerializer s;
	UnserialInfo info(&s);
	info.print = stdout;
	info.install_uniques = info.ignore_callbacks = true;
	s.Read(&info, file, false);
	}

#endif

////////////////////////////

// If true (set by signal handler), we will log some stats to parent.
static bool log_stats = false;
static bool log_prof = false;

// How often stats are sent (in seconds).
// Perhaps we should make this configurable...
const int STATS_INTERVAL = 60;

static RETSIGTYPE sig_handler_log(int signo)
	{
	// SIGALRM is the only one we get.
	log_stats = true;
	}

static RETSIGTYPE sig_handler_prof(int signo)
	{
	log_prof = true;
	}

SocketComm::SocketComm()
	{
	io = 0;

	// We start the ID counter high so that IDs assigned by us
	// (hopefully) don't conflict with those of our parent.
	id_counter = 10000;
	parent_peer = 0;
	parent_msgstate = TYPE;
	parent_id = RemoteSerializer::PEER_NONE;
	parent_msgtype = 0;
	parent_args = 0;
	shutting_conns_down = false;
	terminating = false;
	killing = false;

	listen_port = 0;
	listen_ssl = false;
	enable_ipv6 = false;
	bind_retry_interval = 0;
	listen_next_try = 0;

	// We don't want to use the signal handlers of our parent.
	(void) setsignal(SIGTERM, SIG_DFL);
	(void) setsignal(SIGINT, SIG_DFL);
	(void) setsignal(SIGUSR1, SIG_DFL);
	(void) setsignal(SIGUSR2, SIG_DFL);
	(void) setsignal(SIGCONT, SIG_DFL);
	(void) setsignal(SIGCHLD, SIG_DFL);

	// Raping SIGPROF for profiling
	(void) setsignal(SIGPROF, sig_handler_prof);
	(void) setsignal(SIGALRM, sig_handler_log);
	alarm(STATS_INTERVAL);
	}

SocketComm::~SocketComm()
	{
	loop_over_list(peers, i)
		delete peers[i]->io;

	delete io;
	CloseListenFDs();
	}

static unsigned int first_rtime = 0;

void SocketComm::Run()
	{
	first_rtime = (unsigned int) current_time(true);

	while ( true )
		{
		// Logging signaled?
		if ( log_stats )
			LogStats();

		// Termination signaled
		if ( terminating )
			CheckFinished();

		// Build FDSets for select.
		fd_set fd_read, fd_write, fd_except;

		FD_ZERO(&fd_read);
		FD_ZERO(&fd_write);
		FD_ZERO(&fd_except);

		int max_fd = 0;

		FD_SET(io->Fd(), &fd_read);
		max_fd = io->Fd();

		loop_over_list(peers, i)
			{
			if ( peers[i]->connected )
				{
				FD_SET(peers[i]->io->Fd(), &fd_read);
				if ( peers[i]->io->Fd() > max_fd )
					max_fd = peers[i]->io->Fd();
				}
			else
				{
				if ( peers[i]->next_try > 0 &&
				     time(0) > peers[i]->next_try )
					// Try reconnect.
					Connect(peers[i]);
				}
			}

		if ( listen_next_try && time(0) > listen_next_try  )
			Listen();

		for ( size_t i = 0; i < listen_fds.size(); ++i )
			{
			FD_SET(listen_fds[i], &fd_read);
			if ( listen_fds[i] > max_fd )
				max_fd = listen_fds[i];
			}

		if ( io->IsFillingUp() && ! shutting_conns_down )
			{
			Error("queue to parent filling up; shutting down heaviest connection");

			const ChunkedIO::Statistics* stats = 0;
			unsigned long max = 0;
			Peer* max_peer = 0;

			loop_over_list(peers, i)
				{
				if ( ! peers[i]->connected )
					continue;

				stats = peers[i]->io->Stats();
				if ( stats->bytes_read > max )
					{
					max = stats->bytes_read;
					max_peer = peers[i];
					}
				}

			if ( max_peer )
				CloseConnection(max_peer, true);

			shutting_conns_down = true;
			}

		if ( ! io->IsFillingUp() && shutting_conns_down )
			shutting_conns_down = false;

		// We cannot rely solely on select() as the there may
		// be some data left in our input/output queues. So, we use
		// a small timeout for select and check for data
		// manually afterwards.

		static long selects = 0;
		static long canwrites = 0;
		static long timeouts = 0;

		++selects;
		if ( io->CanWrite() )
			++canwrites;

		// FIXME: Fine-tune this (timeouts, flush, etc.)
		struct timeval small_timeout;
		small_timeout.tv_sec = 0;
		small_timeout.tv_usec =
			io->CanWrite() || io->CanRead() ? 1 : 10;

#if 0
		if ( ! io->CanWrite() )
			usleep(10);
#endif

		int a = select(max_fd + 1, &fd_read, &fd_write, &fd_except,
				&small_timeout);

		if ( a == 0 )
			++timeouts;

		if ( selects % 100000 == 0 )
			Log(fmt("selects=%ld canwrites=%ld timeouts=%ld", selects, canwrites, timeouts));

		if ( a < 0 )
			// Ignore errors for now.
			continue;

		if ( io->CanRead() )
			ProcessParentMessage();

		io->Flush();

		loop_over_list(peers, j)
			{
			// We have to be careful here as the peer may
			// be removed when an error occurs.
			Peer* current = peers[j];
			int round = 0;
			while ( ++round <= 10 && j < peers.length() &&
				peers[j] == current && current->connected &&
				current->io->CanRead() )
				{
				ProcessRemoteMessage(current);
				}
			}

		for ( size_t i = 0; i < listen_fds.size(); ++i )
			if ( FD_ISSET(listen_fds[i], &fd_read) )
				AcceptConnection(listen_fds[i]);

		// Hack to display CPU usage of the child, triggered via
		// SIGPROF.
		static unsigned int first_rtime = 0;
		if ( first_rtime == 0 )
			first_rtime = (unsigned int) current_time(true);

		if ( log_prof )
			{
			LogProf();
			log_prof = false;
			}
		}
	}

bool SocketComm::ProcessParentMessage()
	{
	switch ( parent_msgstate ) {
	case TYPE:
		{
		parent_peer = 0;
		parent_msgtype = MSG_NONE;

		// CMsg follows
		ChunkedIO::Chunk* c;
		if ( ! io->Read(&c) )
			{
			if ( io->Eof() )
				Error("parent died", true);

			Error(fmt("can't read parent's cmsg: %s",
					io->Error()), true);
			return false;
			}

		if ( ! c )
			return true;

		CMsg* msg = (CMsg*) c->data;
		parent_peer = LookupPeer(msg->Peer(), false);
		parent_id = msg->Peer();
		parent_msgtype = msg->Type();
		parent_args = 0;

		delete c;

		switch ( parent_msgtype ) {
		case MSG_LISTEN_STOP:
		case MSG_CLOSE:
		case MSG_CLOSE_ALL:
		case MSG_TERMINATE:
		case MSG_PHASE_DONE:
		case MSG_DEBUG_DUMP:
		case MSG_REQUEST_LOGS:
			{
			// No further argument chunk.
			parent_msgstate = TYPE;
			return DoParentMessage();
			}

		case MSG_LISTEN:
		case MSG_CONNECT_TO:
		case MSG_COMPRESS:
		case MSG_PING:
		case MSG_PONG:
		case MSG_REQUEST_EVENTS:
		case MSG_REQUEST_SYNC:
		case MSG_SERIAL:
		case MSG_CAPTURE_FILTER:
		case MSG_VERSION:
		case MSG_CAPS:
		case MSG_SYNC_POINT:
		case MSG_REMOTE_PRINT:
		case MSG_LOG_CREATE_WRITER:
		case MSG_LOG_WRITE:
			{
			// One further argument chunk.
			parent_msgstate = ARGS;
			return ProcessParentMessage();
			}

		default:
			InternalError(fmt("unknown msg type %d", parent_msgtype));
			return true;
		}
		}

	case ARGS:
		{
		// Argument chunk follows.
		ChunkedIO::Chunk* c = 0;
		READ_CHUNK(io, c, Error("parent died", true));
		parent_args = c;
		parent_msgstate = TYPE;
		bool result = DoParentMessage();

		if ( parent_args )
			{
			delete parent_args;
			parent_args = 0;
			}

		return result;
		}

	default:
		InternalError("unknown msgstate");
	}

	// Cannot be reached.
	return false;
	}

bool SocketComm::DoParentMessage()
	{
	switch ( parent_msgtype ) {

	case MSG_LISTEN_STOP:
		{
		CloseListenFDs();

		Log("stopped listening");

		return true;
		}

	case MSG_CLOSE:
		{
		if ( parent_peer && parent_peer->connected )
			CloseConnection(parent_peer, false);
		return true;
		}

	case MSG_CLOSE_ALL:
		{
		loop_over_list(peers, i)
			{
			if ( peers[i]->connected )
				CloseConnection(peers[i], false);
			}
		return true;
		}

	case MSG_TERMINATE:
		{
		terminating = true;
		CheckFinished();
		return true;
		}

	case MSG_DEBUG_DUMP:
		{
#ifdef DEBUG_COMMUNICATION
		io->DumpDebugData("comm-dump.child.pipe", true);
		io->DumpDebugData("comm-dump.child.pipe", false);

		loop_over_list(peers, j)
			{
			RemoteSerializer::PeerID id = peers[j]->id;
			peers[j]->io->DumpDebugData(fmt("comm-dump.child.peer.%d", id), true);
			peers[j]->io->DumpDebugData(fmt("comm-dump.child.peer.%d", id), false);
			}
#else
		InternalError("DEBUG_DUMP support not compiled in");
#endif
		return true;
		}

	case MSG_LISTEN:
		return ProcessListen();

	case MSG_CONNECT_TO:
		return ProcessConnectTo();

	case MSG_COMPRESS:
		return ProcessParentCompress();

	case MSG_PING:
		{
		// Set time2.
		assert(parent_args);
		ping_args* args = (ping_args*) parent_args->data;
		args->time2 = htond(current_time(true));
		return ForwardChunkToPeer();
		}

	case MSG_PONG:
		{
		assert(parent_args);
		// Calculate time delta.
		ping_args* args = (ping_args*) parent_args->data;
		args->time3 = htond(current_time(true) - ntohd(args->time3));
		return ForwardChunkToPeer();
		}

	case MSG_PHASE_DONE:
	case MSG_REQUEST_LOGS:
		{
		// No argument block follows.
		if ( parent_peer && parent_peer->connected )
			{
			DEBUG_COMM(fmt("child: forwarding %s to peer", msgToStr(parent_msgtype)));
			if ( ! SendToPeer(parent_peer, parent_msgtype, 0) )
				return false;
			}

		return true;
		}

	case MSG_REQUEST_EVENTS:
	case MSG_REQUEST_SYNC:
	case MSG_SERIAL:
	case MSG_CAPTURE_FILTER:
	case MSG_VERSION:
	case MSG_CAPS:
	case MSG_SYNC_POINT:
	case MSG_REMOTE_PRINT:
	case MSG_LOG_CREATE_WRITER:
	case MSG_LOG_WRITE:
		assert(parent_args);
		return ForwardChunkToPeer();

	default:
		InternalError("ProcessParentMessage: unexpected state");
	}

	InternalError("cannot be reached");
	return false;
	}

bool SocketComm::ForwardChunkToPeer()
	{
	char state = parent_msgtype;

	if ( parent_peer && parent_peer->connected )
		{
		DEBUG_COMM("child: forwarding with 1 arg to peer");

		if ( ! SendToPeer(parent_peer, state, 0) )
			return false;

		if ( ! SendToPeer(parent_peer, parent_args) )
			return false;

		parent_args = 0;
		}
	else
		{
#ifdef DEBUG
		if ( parent_peer )
			DEBUG_COMM(fmt("child: not connected to #%" PRI_SOURCE_ID, parent_id));
#endif
		}

	return true;
	}

bool SocketComm::ProcessConnectTo()
	{
	assert(parent_args);
	vector<string> args = tokenize(parent_args->data, ',');

	if ( args.size() != 6 )
		{
		Error(fmt("ProcessConnectTo() bad number of arguments"));
		return false;
		}

	Peer* peer = new Peer;

	if ( ! atoi_n(args[0].size(), args[0].c_str(), 0, 10, peer->id) )
		{
		Error(fmt("ProccessConnectTo() bad peer id string"));
		delete peer;
		return false;
		}

	peer->ip = IPAddr(args[1]);
	peer->zone_id = args[2];

	if ( ! atoi_n(args[3].size(), args[3].c_str(), 0, 10, peer->port) )
		{
		Error(fmt("ProcessConnectTo() bad peer port string"));
		delete peer;
		return false;
		}

	if ( ! atoi_n(args[4].size(), args[4].c_str(), 0, 10, peer->retry) )
		{
		Error(fmt("ProcessConnectTo() bad peer retry string"));
		delete peer;
		return false;
		}

	peer->ssl = false;
	if ( args[5] != "0" )
		peer->ssl = true;

	return Connect(peer);
	}

bool SocketComm::ProcessListen()
	{
	assert(parent_args);
	vector<string> args = tokenize(parent_args->data, ',');

	if ( args.size() != 6 )
		{
		Error(fmt("ProcessListen() bad number of arguments"));
		return false;
		}

	listen_if = args[0];

	if ( ! atoi_n(args[1].size(), args[1].c_str(), 0, 10, listen_port) )
		{
		Error(fmt("ProcessListen() bad peer port string"));
		return false;
		}

	listen_ssl = false;
	if ( args[2] != "0" )
		listen_ssl = true;

	enable_ipv6 = false;
	if ( args[3] != "0" )
		enable_ipv6 = true;

	listen_zone_id = args[4];

	if ( ! atoi_n(args[5].size(), args[5].c_str(), 0, 10, bind_retry_interval) )
		{
		Error(fmt("ProcessListen() bad peer port string"));
		return false;
		}

	return Listen();
	}

bool SocketComm::ProcessParentCompress()
	{
	assert(parent_args);
	uint32* args = (uint32*) parent_args->data;

	uint32 level = ntohl(args[0]);

	if ( ! parent_peer->compressor )
		{
		parent_peer->io = new CompressedChunkedIO(parent_peer->io);
		parent_peer->io->Init();
		parent_peer->compressor = true;
		}

	// Signal compression to peer.
	if ( ! SendToPeer(parent_peer, MSG_COMPRESS, 0) )
		return false;

	// This cast is safe.
	CompressedChunkedIO* comp_io = (CompressedChunkedIO*) parent_peer->io;
	comp_io->EnableCompression(level);

	Log(fmt("enabling compression (level %d)", level), parent_peer);

	return true;
	}

bool SocketComm::ProcessRemoteMessage(SocketComm::Peer* peer)
	{
	assert(peer);

	peer->io->Flush();

	switch ( peer->state ) {
	case MSG_NONE:
		{ // CMsg follows
		ChunkedIO::Chunk* c;
		READ_CHUNK(peer->io, c,
			(CloseConnection(peer, true), peer))

		CMsg* msg = (CMsg*) c->data;

		DEBUG_COMM(fmt("child: %s from peer #%" PRI_SOURCE_ID,
				msgToStr(msg->Type()), peer->id));

		switch ( msg->Type() ) {
		case MSG_PHASE_DONE:
		case MSG_REQUEST_LOGS:
			// No further argument block.
			DEBUG_COMM("child: forwarding with 0 args to parent");
			if ( ! SendToParent(msg->Type(), peer, 0) )
				return false;
			break;

		default:
			peer->state = msg->Type();
		}

		delete c;

		break;
		}

	case MSG_COMPRESS:
		ProcessPeerCompress(peer);
		break;

	case MSG_PING:
		{
		// Messages with one further argument block which we simply
		// forward to our parent.
		ChunkedIO::Chunk* c;
		READ_CHUNK(peer->io, c,
			(CloseConnection(peer, true), peer))

		// Set time3.
		ping_args* args = (ping_args*) c->data;
		args->time3 = htond(current_time(true));
		return ForwardChunkToParent(peer, c);
		}

	case MSG_PONG:
		{
		// Messages with one further argument block which we simply
		// forward to our parent.
		ChunkedIO::Chunk* c;
		READ_CHUNK(peer->io, c,
			(CloseConnection(peer, true), peer))

		// Calculate time delta.
		ping_args* args = (ping_args*) c->data;
		args->time2 = htond(current_time(true) - ntohd(args->time2));
		return ForwardChunkToParent(peer, c);
		}

	case MSG_REQUEST_EVENTS:
	case MSG_REQUEST_SYNC:
	case MSG_SERIAL:
	case MSG_CAPTURE_FILTER:
	case MSG_VERSION:
	case MSG_CAPS:
	case MSG_SYNC_POINT:
	case MSG_REMOTE_PRINT:
	case MSG_LOG_CREATE_WRITER:
	case MSG_LOG_WRITE:
		{
		// Messages with one further argument block which we simply
		// forward to our parent.
		ChunkedIO::Chunk* c;
		READ_CHUNK(peer->io, c,
			(CloseConnection(peer, true), peer))

		return ForwardChunkToParent(peer, c);
		}

	default:
		InternalError("ProcessRemoteMessage: unexpected state");
	}

	return true;
	}

bool SocketComm::ForwardChunkToParent(Peer* peer, ChunkedIO::Chunk* c)
	{
	char state = peer->state;
	peer->state = MSG_NONE;

	DEBUG_COMM("child: forwarding message with 1 arg to parent");

	if ( ! SendToParent(state, peer, 0) )
		return false;

	if ( ! SendToParent(c) )
		return false;

	io->Flush(); // FIXME: Needed?
	return true;
	}

bool SocketComm::ProcessPeerCompress(Peer* peer)
	{
	peer->state = MSG_NONE;

	if ( ! parent_peer->compressor )
		{
		parent_peer->io = new CompressedChunkedIO(parent_peer->io);
		parent_peer->io->Init();
		parent_peer->compressor = true;
		}

	// This cast is safe here.
	((CompressedChunkedIO*) peer->io)->EnableDecompression();
	Log("enabling decompression", peer);
	return true;
	}

bool SocketComm::Connect(Peer* peer)
	{
	int status;
	addrinfo hints, *res, *res0;
        memset(&hints, 0, sizeof(hints));

	hints.ai_family = PF_UNSPEC;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST;

	char port_str[16];
	modp_uitoa10(peer->port, port_str);

	string gaihostname(peer->ip.AsString());
	if ( peer->zone_id != "" )
		gaihostname.append("%").append(peer->zone_id);

	status = getaddrinfo(gaihostname.c_str(), port_str, &hints, &res0);
	if ( status != 0 )
		{
		Error(fmt("getaddrinfo error: %s", gai_strerror(status)));
		return false;
		}

	int sockfd = -1;
	for ( res = res0; res; res = res->ai_next )
		{
		sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if ( sockfd < 0 )
			{
			Error(fmt("can't create connect socket, %s", strerror(errno)));
			continue;
			}

		if ( connect(sockfd, res->ai_addr, res->ai_addrlen) < 0 )
			{
			Error(fmt("connect failed: %s", strerror(errno)), peer);
			safe_close(sockfd);
			sockfd = -1;
			continue;
			}

		break;
		}

	freeaddrinfo(res0);

	bool connected = sockfd != -1;

	if ( ! (connected || peer->retry) )
		{
		CloseConnection(peer, false);
		return false;
		}

	Peer* existing_peer = LookupPeer(peer->id, false);
	if ( existing_peer )
		{
		*existing_peer = *peer;
		peer = existing_peer;
		}
	else
		peers.append(peer);

	peer->connected = connected;
	peer->next_try = connected ? 0 : time(0) + peer->retry;
	peer->state = MSG_NONE;
	peer->io = 0;
	peer->compressor = false;

	if ( connected )
		{
		if ( peer->ssl )
			peer->io = new ChunkedIOSSL(sockfd, false);
		else
			peer->io = new ChunkedIOFd(sockfd, "child->peer");

		if ( ! peer->io->Init() )
			{
			Error(fmt("can't init peer io: %s",
					peer->io->Error()), false);
			return 0;
			}
		}

	if ( connected )
		{
		Log("connected", peer);

		const size_t BUFSIZE = 1024;
		char* data = new char[BUFSIZE];
		snprintf(data, BUFSIZE, "%s,%"PRIu32, peer->ip.AsString().c_str(),
		         peer->port);

		if ( ! SendToParent(MSG_CONNECTED, peer, data) )
			return false;
		}

	return connected;
	}

bool SocketComm::CloseConnection(Peer* peer, bool reconnect)
	{
	if ( ! SendToParent(MSG_CLOSE, peer, 0) )
		return false;

	Log("connection closed", peer);

	if ( ! peer->retry || ! reconnect )
		{
		peers.remove(peer);
		delete peer->io; // This will close the fd.
		delete peer;
		}
	else
		{
		delete peer->io; // This will close the fd.
		peer->io = 0;
		peer->connected = false;
		peer->next_try = time(0) + peer->retry;
		}

	if ( parent_peer == peer )
		{
		parent_peer = 0;
		parent_id = RemoteSerializer::PEER_NONE;
		}

	return true;
	}

bool SocketComm::Listen()
	{
	int status, on = 1;
	addrinfo hints, *res, *res0;
        memset(&hints, 0, sizeof(hints));

	IPAddr listen_ip(listen_if);

	if ( enable_ipv6 )
		{
		if ( listen_ip == IPAddr("0.0.0.0") || listen_ip == IPAddr("::") )
			hints.ai_family = PF_UNSPEC;
		else
			hints.ai_family = (listen_ip.GetFamily() == IPv4 ? PF_INET : PF_INET6);
		}
	else
		hints.ai_family = PF_INET;

	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

	char port_str[16];
	modp_uitoa10(listen_port, port_str);

	string scoped_addr(listen_if);
	if ( listen_zone_id != "" )
		scoped_addr.append("%").append(listen_zone_id);

	const char* addr_str = 0;
	if ( listen_ip != IPAddr("0.0.0.0") && listen_ip != IPAddr("::") )
		addr_str = scoped_addr.c_str();

	CloseListenFDs();

	if ( (status = getaddrinfo(addr_str, port_str, &hints, &res0)) != 0 )
		{
		Error(fmt("getaddrinfo error: %s", gai_strerror(status)));
		return false;
		}

	for ( res = res0; res; res = res->ai_next )
		{
		if ( res->ai_family != AF_INET && res->ai_family != AF_INET6 )
			{
			Error(fmt("can't create listen socket: unknown address family, %d",
			          res->ai_family));
			continue;
			}

		IPAddr a = (res->ai_family == AF_INET) ?
				IPAddr(((sockaddr_in*)res->ai_addr)->sin_addr) :
				IPAddr(((sockaddr_in6*)res->ai_addr)->sin6_addr);

		string l_addr_str(a.AsURIString());
		if ( listen_zone_id != "")
			l_addr_str.append("%").append(listen_zone_id);

		int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if ( fd < 0 )
			{
			Error(fmt("can't create listen socket, %s", strerror(errno)));
			continue;
			}

		if ( setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0 )
			Error(fmt("can't set SO_REUSEADDR, %s", strerror(errno)));

		// For IPv6 listening sockets, we don't want do dual binding to also
		// get IPv4-mapped addresses because that's not as portable. e.g.
		// many BSDs don't allow that.
		if ( res->ai_family == AF_INET6 &&
		     setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0 )
			Error(fmt("can't set IPV6_V6ONLY, %s", strerror(errno)));

		if ( bind(fd, res->ai_addr, res->ai_addrlen) < 0 )
			{
			Error(fmt("can't bind to %s:%s, %s", l_addr_str.c_str(),
			          port_str, strerror(errno)));

			if ( errno == EADDRINUSE )
				{
				// Abandon completely this attempt to set up listening sockets,
				// try again later.
				safe_close(fd);
				CloseListenFDs();
				listen_next_try = time(0) + bind_retry_interval;
				return false;
				}

			safe_close(fd);
			continue;
			}

		if ( listen(fd, 50) < 0 )
			{
			Error(fmt("can't listen on %s:%s, %s", l_addr_str.c_str(),
			          port_str, strerror(errno)));
			safe_close(fd);
			continue;
			}

		listen_fds.push_back(fd);
		Log(fmt("listening on %s:%s (%s)", l_addr_str.c_str(), port_str,
		        listen_ssl ? "ssl" : "clear"));
		}

	freeaddrinfo(res0);

	listen_next_try = 0;
	return listen_fds.size() > 0;
	}

bool SocketComm::AcceptConnection(int fd)
	{
	union {
		sockaddr_storage ss;
		sockaddr_in s4;
		sockaddr_in6 s6;
	} client;

	socklen_t len = sizeof(client.ss);

	int clientfd = accept(fd, (sockaddr*) &client.ss, &len);
	if ( clientfd < 0 )
		{
		Error(fmt("accept failed, %s %d", strerror(errno), errno));
		return false;
		}

	if ( client.ss.ss_family != AF_INET && client.ss.ss_family != AF_INET6 )
		{
		Error(fmt("accept fail, unknown address family %d",
		          client.ss.ss_family));
		safe_close(clientfd);
		return false;
		}

	Peer* peer = new Peer;
	peer->id = id_counter++;
	peer->ip = client.ss.ss_family == AF_INET ?
	           IPAddr(client.s4.sin_addr) :
	           IPAddr(client.s6.sin6_addr);

	peer->port = client.ss.ss_family == AF_INET ?
	             ntohs(client.s4.sin_port) :
	             ntohs(client.s6.sin6_port);

	peer->connected = true;
	peer->ssl = listen_ssl;
	peer->compressor = false;

	if ( peer->ssl )
		peer->io = new ChunkedIOSSL(clientfd, true);
	else
		peer->io = new ChunkedIOFd(clientfd, "child->peer");

	if ( ! peer->io->Init() )
		{
		Error(fmt("can't init peer io: %s", peer->io->Error()), false);
		delete peer->io;
		delete peer;
		return false;
		}

	peers.append(peer);

	Log(fmt("accepted %s connection", peer->ssl ? "SSL" : "clear"), peer);

	const size_t BUFSIZE = 1024;
	char* data = new char[BUFSIZE];
	snprintf(data, BUFSIZE, "%s,%"PRIu32, peer->ip.AsString().c_str(),
	         peer->port);

	if ( ! SendToParent(MSG_CONNECTED, peer, data) )
		return false;

	return true;
	}

const char* SocketComm::MakeLogString(const char* msg, Peer* peer)
	{
	const int BUFSIZE = 1024;
	static char* buffer = 0;

	if ( ! buffer )
		buffer = new char[BUFSIZE];

	int len = 0;

	if ( peer )
		{
		string scoped_addr(peer->ip.AsURIString());
		if ( peer->zone_id != "" )
			scoped_addr.append("%").append(peer->zone_id);

		len = snprintf(buffer, BUFSIZE, "[#%d/%s:%d] ", int(peer->id),
		               scoped_addr.c_str(), peer->port);
		}

	len += safe_snprintf(buffer + len, BUFSIZE - len, "%s", msg);
	return buffer;
	}

void SocketComm::CloseListenFDs()
	{
	for ( size_t i = 0; i < listen_fds.size(); ++i )
		safe_close(listen_fds[i]);

	listen_fds.clear();
	}

void SocketComm::Error(const char* msg, bool kill_me)
	{
	if ( kill_me )
		{
		fprintf(stderr, "fatal error in child: %s\n", msg);
		Kill();
		}
	else
		{
		if ( io->Eof() )
			// Can't send to parent, so fall back to stderr.
			fprintf(stderr, "error in child: %s", msg);
		else
			SendToParent(MSG_ERROR, 0, copy_string(msg));
		}

	DEBUG_COMM(fmt("child: %s", msg));
	}

bool SocketComm::Error(const char* msg, Peer* peer)
	{
	const char* buffer = MakeLogString(msg, peer);
	Error(buffer);

	// If a remote peer causes an error, we shutdown the connection
	// as resynchronizing is in general not possible. But we may
	// try again later.
	if ( peer->connected )
		CloseConnection(peer, true);

	return true;
	}

void SocketComm::Log(const char* msg, Peer* peer)
	{
	const char* buffer = MakeLogString(msg, peer);
	SendToParent(MSG_LOG, 0, copy_string(buffer));
	DEBUG_COMM(fmt("child: %s", buffer));
	}

void SocketComm::InternalError(const char* msg)
	{
	fprintf(stderr, "internal error in child: %s\n", msg);
	Kill();
	}

void SocketComm::Kill()
	{
	if ( killing )
		// Ignore recursive calls.
		return;

	killing = true;

	LogProf();
	Log("terminating");

	CloseListenFDs();

	if ( kill(getpid(), SIGTERM) < 0 )
		Log(fmt("warning: cannot kill SocketComm pid %d, %s", getpid(), strerror(errno)));

	while ( 1 )
		; // loop until killed
	}

SocketComm::Peer* SocketComm::LookupPeer(RemoteSerializer::PeerID id,
						bool only_if_connected)
	{
	loop_over_list(peers, i)
		if ( peers[i]->id == id )
			return ! only_if_connected ||
				peers[i]->connected ? peers[i] : 0;
	return 0;
	}

bool SocketComm::LogStats()
	{
	if ( ! peers.length() )
		return true;

	// Concat stats of all peers into single buffer.
	char* buffer = new char[peers.length() * 512];
	int pos = 0;

	loop_over_list(peers, i)
		{
		if ( peers[i]->connected )
			peers[i]->io->Stats(buffer+pos, 512);
		else
			strcpy(buffer+pos, "not connected");
		pos += strlen(buffer+pos) + 1;
		}

	// Send it.
	if ( ! SendToParent(MSG_STATS, 0, buffer, pos) )
		return false;

	log_stats = false;
	alarm(STATS_INTERVAL);
	return true;
	}

bool SocketComm::LogProf()
	{
	static struct rusage cld_res;
	getrusage(RUSAGE_SELF, &cld_res);

	double Utime = cld_res.ru_utime.tv_sec + cld_res.ru_utime.tv_usec / 1e6;
	double Stime = cld_res.ru_stime.tv_sec + cld_res.ru_stime.tv_usec / 1e6;
	double Rtime = current_time(true);

	SocketComm::Log(fmt("CPU usage: user %.03f sys %.03f real %0.03f",
				Utime, Stime, Rtime - first_rtime));

	return true;
	}

void SocketComm::CheckFinished()
	{
	assert(terminating);

	loop_over_list(peers, i)
		{
		if ( ! peers[i]->connected )
			continue;
		if ( ! peers[i]->io->IsIdle() )
			return;
		}

	LogProf();
	Log("terminating");

	// All done.
	SendToParent(MSG_TERMINATE, 0, 0);
	}

bool SocketComm::SendToParent(char type, Peer* peer, const char* str, int len)
	{
#ifdef DEBUG
	// str  may already by constructed with fmt()
	const char* tmp = copy_string(str);
	DEBUG_COMM(fmt("child: (->parent) %s (#%" PRI_SOURCE_ID ", %s)", msgToStr(type), peer ? peer->id : RemoteSerializer::PEER_NONE, tmp));
	delete [] tmp;
#endif
	if ( sendToIO(io, type, peer ? peer->id : RemoteSerializer::PEER_NONE,
			str, len) )
		return true;

	if ( io->Eof() )
		Error("parent died", true);

	return false;
	}

bool SocketComm::SendToParent(char type, Peer* peer, int nargs, ...)
	{
	va_list ap;

#ifdef DEBUG
	va_start(ap,nargs);
	DEBUG_COMM(fmt("child: (->parent) %s (#%" PRI_SOURCE_ID ",%s)", msgToStr(type), peer ? peer->id : RemoteSerializer::PEER_NONE, fmt_uint32s(nargs, ap)));
	va_end(ap);
#endif

	va_start(ap, nargs);
	bool ret = sendToIO(io, type,
				peer ? peer->id : RemoteSerializer::PEER_NONE,
				nargs, ap);
	va_end(ap);

	if ( ret )
		return true;

	if ( io->Eof() )
		Error("parent died", true);

	return false;
	}

bool SocketComm::SocketComm::SendToParent(ChunkedIO::Chunk* c)
	{
	DEBUG_COMM(fmt("child: (->parent) chunk of size %d", c->len));
	if ( sendToIO(io, c) )
		return true;

	if ( io->Eof() )
		Error("parent died", true);

	return false;
	}

bool SocketComm::SendToPeer(Peer* peer, char type, const char* str, int len)
	{
#ifdef DEBUG
	// str  may already by constructed with fmt()
	const char* tmp = copy_string(str);
	DEBUG_COMM(fmt("child: (->peer) %s to #%" PRI_SOURCE_ID " (%s)", msgToStr(type), peer->id, tmp));
	delete [] tmp;
#endif

	if ( ! sendToIO(peer->io, type, RemoteSerializer::PEER_NONE, str, len) )
		{
		Error(fmt("child: write error %s", io->Error()), peer);
		return false;
		}

	return true;
	}

bool SocketComm::SendToPeer(Peer* peer, char type, int nargs, ...)
	{
	va_list ap;

#ifdef DEBUG
	va_start(ap,nargs);
	DEBUG_COMM(fmt("child: (->peer) %s to #%" PRI_SOURCE_ID " (%s)",
			msgToStr(type), peer->id, fmt_uint32s(nargs, ap)));
	va_end(ap);
#endif

	va_start(ap, nargs);
	bool ret = sendToIO(peer->io, type, RemoteSerializer::PEER_NONE,
				nargs, ap);
	va_end(ap);

	if ( ! ret )
		{
		Error(fmt("child: write error %s", io->Error()), peer);
		return false;
		}

	return true;
	}

bool SocketComm::SendToPeer(Peer* peer, ChunkedIO::Chunk* c)
	{
	DEBUG_COMM(fmt("child: (->peer) chunk of size %d to #%" PRI_SOURCE_ID, c->len, peer->id));
	if ( ! sendToIO(peer->io, c) )
		{
		Error(fmt("child: write error %s", io->Error()), peer);
		return false;
		}

	return true;
	}
