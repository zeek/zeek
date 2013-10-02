// Helper classes to pass data between serialization methods.

#ifndef serialinfo_h
#define serialinfo_h

class SerialInfo {
public:
	SerialInfo(Serializer* arg_s)
		{
		chunk = 0;
		s = arg_s;
		may_suspend = clear_containers = false;
		cache = globals_as_names = true;
		type = SER_NONE;
		pid_32bit = false;
		include_locations = true;
		new_cache_strategy = false;
		broccoli_peer = false;
		}

	SerialInfo(const SerialInfo& info)
		{
		chunk = info.chunk;
		s = info.s;
		may_suspend = info.may_suspend;
		cache = info.cache;
		type = info.type;
		clear_containers = info.clear_containers;
		globals_as_names = info.globals_as_names;
		pid_32bit = info.pid_32bit;
		include_locations = info.include_locations;
		new_cache_strategy = info.new_cache_strategy;
		broccoli_peer = info.broccoli_peer;
		}

	// Parameters that control serialization.
	Serializer* s;	// serializer to use
	bool cache;	// true if object caching is ok
	bool may_suspend;	// if true, suspending serialization is ok
	bool clear_containers;	// if true, store container values as empty
	bool include_locations;	// if true, include locations in serialization

	// If true, for NameExpr's serialize just the names of globals, just
	// their value.
	bool globals_as_names;

	bool pid_32bit;	// if true, use old-style 32-bit permanent IDs

	// If true, we support keeping objs in cache permanently.
	bool new_cache_strategy;

	// If true, we're connecting to a Broccoli. If so, serialization
	// specifics may be adapted for functionality Broccoli does not
	// support.
	bool broccoli_peer;

	ChunkedIO::Chunk* chunk; // chunk written right before the serialization

	// Attributes set during serialization.
	SerialType type;	// type of currently serialized object

	// State for suspending/resuming serialization
	Continuation cont;
};

class UnserialInfo {
public:
	UnserialInfo(Serializer* arg_s)
		{
		s = arg_s;
		cache = true;
		type = SER_NONE;
		chunk = 0;
		install_globals = install_conns = true;
		install_uniques = false;
		ignore_callbacks = false;
		id_policy = Replace;
		print = 0;
		pid_32bit = false;
		new_cache_strategy = false;
		broccoli_peer = false;
		}

	UnserialInfo(const UnserialInfo& info)
		{
		s = info.s;
		cache = info.cache;
		type = info.type;
		chunk = info.chunk;
		install_globals = info.install_globals;
		install_uniques = info.install_uniques;
		install_conns = info.install_conns;
		ignore_callbacks = info.ignore_callbacks;
		id_policy = info.id_policy;
		print = info.print;
		pid_32bit = info.pid_32bit;
		new_cache_strategy = info.new_cache_strategy;
		broccoli_peer = info.broccoli_peer;
		}

	// Parameters that control unserialization.
	Serializer* s;	// serializer to use
	bool cache;	// if true,  object caching is ok
	FILE* print;	// print read objects to given file (human-readable)

	ChunkedIO::Chunk* chunk; // chunk to parse (rather than reading one)

	bool install_globals;	// if true, install unknown globals
				// in global scope
	bool install_conns;	// if true, add connections to session table
	bool install_uniques;	// if true, install unknown globally
				// unique IDs in global scope
	bool ignore_callbacks;	// if true, don't call Got*() callbacks
	bool pid_32bit; // if true, use old-style 32-bit permanent IDs.

	// If true, we support keeping objs in cache permanently.
	bool new_cache_strategy;

	// If true, we're connecting to a Broccoli. If so, serialization
	// specifics may be adapted for functionality Broccoli does not
	// support.
	bool broccoli_peer;

	// If a global ID already exits, of these policies is used.
	enum {
		Keep,	// keep the old ID and ignore the new
		Replace,	// install the new ID (default)

		// Keep current ID instance but copy the new value into it
		// (types have to match).
		CopyNewToCurrent,

		// Install the new ID instance but replace its value
		// with that of the old one (types have to match).
		CopyCurrentToNew,

		// Instantiate a new ID, but do not insert it into the global
		// space.
		InstantiateNew,
	} id_policy;

	// Attributes set during unserialization.
	SerialType type;	// type of currently unserialized object
};

// Helper class to temporarily disable suspending for all next-level calls
// using the given SerialInfo.  It saves the current value of info.may_suspend
// and then sets it to false.  When it goes out of scope, the original value
// is restored.
//
// We need this because not all classes derived from SerialObj are
// suspension-aware yet, i.e., they don't work correctly if one of the
// next-level functions suspends. Eventually this may change, but actually
// it's not very important: most classes don't need to suspend anyway as
// their data volume is very small.  We have to make sure though that those
// which do (e.g. TableVals) support suspension.
class DisableSuspend {
public:
	DisableSuspend(SerialInfo* arg_info)
		{
		info = arg_info;
		old_may_suspend = info->may_suspend;
		info->may_suspend = false;
		}

	~DisableSuspend()	{ Restore(); }

	void Release()	{ info = 0; }

	// Restores the suspension-state to its original value.
	void Restore()
		{
		if ( info )
			info->may_suspend = old_may_suspend;
		}

private:
	SerialInfo* info;
	bool old_may_suspend;
};

#endif
