// Implements persistance for Bro's data structures.

#ifndef persistence_serializer_h
#define persistence_serializer_h

#include "Serializer.h"
#include "List.h"

class StateAccess;

class PersistenceSerializer : public FileSerializer {
public:
	PersistenceSerializer();
	virtual ~PersistenceSerializer();

	// Define the directory where to store the data.
	void SetDir(const char* arg_dir)	{ dir = copy_string(arg_dir); }

	// Register/unregister the ID/connection to be saved by WriteAll().
	void Register(ID* id);
	void Unregister(ID* id);
	void Register(Connection* conn);
	void Unregister(Connection* conn);

	// Read all data that has been changed since last scan of directory.
	// is_init should be true for the first read upon start-up. All existing
	// state will be cleared. If delete_files is true, file which have been
	// read are removed (even if the read was unsuccessful!).
	bool ReadAll(bool is_init, bool delete_files);

	// Each of the following four methods may suspend operation.
	// If they do, they install a Timer which resumes after some
	// amount of time. If a function is called again before it
	// has completely finished its task, it will do nothing and
	// return false.

	bool WriteState(bool may_suspend);

	// Writes Bro's configuration (w/o dynamic state).
	bool WriteConfig(bool may_suspend);

	// Sends all registered state to remote host
	// (by leveraging the remote_serializer).
	bool SendState(SourceID peer, bool may_suspend);

	// Sends Bro's config to remote host
	// (by leveraging the remote_serializer).
	bool SendConfig(SourceID peer, bool may_suspend);

	// Returns true if a serialization is currently running.
	bool IsSerializationRunning() const	{ return running.length(); }

	// Tells the serializer that this access was performed. If a
	// serialization is going on, it may store it.  (Need only be called if
	// IsSerializationRunning() returns true.)
	bool LogAccess(const StateAccess& s);

protected:
	friend class RemoteSerializer;
	friend class IncrementalWriteTimer;

	virtual void GotID(ID* id, Val* val);
	virtual void GotEvent(const char* name, double time,
				EventHandlerPtr event, val_list* args);
	virtual void GotFunctionCall(const char* name, double time,
				Func* func, val_list* args) ;
	virtual void GotStateAccess(StateAccess* s);
	virtual void GotTimer(Timer* t);
	virtual void GotConnection(Connection* c);
	virtual void GotPacket(Packet* packet);

	// If file has changed since last check, read it.
	bool CheckForFile(UnserialInfo* info, const char* file,
				bool delete_file);

	// Returns true if it's a regular file and has a more recent timestamp
	// than last time we checked it.
	bool CheckTimestamp(const char* file);

	// Move file from <dir>/tmp/<file> to <dir>/<file>. Afterwards, call
	// CheckTimestamp() with <dir>/<file>.
	bool MoveFileUp(const char* dir, const char* file);

	// Generates an error message, terminates current serialization,
	// and returns false.
	bool SerialError(const char* msg);

	// Start a new serialization.
	struct SerialStatus;
	bool RunSerialization(SerialStatus* status);

	// Helpers for RunSerialization.
	bool DoIDSerialization(SerialStatus* status, ID* id);
	bool DoConnSerialization(SerialStatus* status, Connection* conn);
	bool DoAccessSerialization(SerialStatus* status, StateAccess* access);

	typedef PDict(ID) id_map;

	declare(PDict, Connection);
	typedef PDict(Connection) conn_map;

	struct SerialStatus {
		enum Type {
			WritingState, WritingConfig,
			SendingState, SendingConfig,
		};

		SerialStatus(Serializer* s, Type arg_type) : info(s)
			{
			type = arg_type;
			ids = 0;
			id_cookie = 0;
			conns = 0;
			conn_cookie = 0;
			peer = SOURCE_LOCAL;
			filename = 0;
			}

		Type type;
		SerialInfo info;

		// IDs to serialize.
		id_map* ids;
		IterCookie* id_cookie;

		// Connections to serialize.
		conn_map* conns;
		IterCookie* conn_cookie;

		// Accesses performed while we're serializing.
		declare(PList,StateAccess);
		typedef PList(StateAccess) state_access_list;
		state_access_list accesses;

		// The ID/Conn we're currently serializing.
		union {
			ID* id;
			Connection* conn;
		} current;

		// Only set if type is Writing{State,Config}.
		const char* filename;

		// Only set if type is Sending{State,Config}.
		SourceID peer;
	};

	const char* dir;

	declare(PList, SerialStatus);
	PList(SerialStatus) running;

	id_map persistent_ids;
	conn_map persistent_conns;

	// To keep track of files' modification times.
	declare(PDict, time_t);
	typedef PDict(time_t) file_map;
	file_map files;
};

extern PersistenceSerializer* persistence_serializer;

#endif
