#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/time.h>
#include <sys/stat.h>

#include "Serializer.h"
#include "Scope.h"
#include "Stmt.h"
#include "Reporter.h"
#include "Func.h"
#include "Event.h"
#include "EventRegistry.h"
#include "SerializationFormat.h"
#include "NetVar.h"
#include "Conn.h"
#include "Timer.h"
#include "RemoteSerializer.h"

Serializer::Serializer(SerializationFormat* arg_format)
	{
	if ( arg_format )
		format = arg_format;
	else
		format = new BinarySerializationFormat();

	io = 0;
	error_descr = 0;
	current_cache = 0;
	}

Serializer::~Serializer()
	{
	delete format;
	delete [] error_descr;
	}

bool Serializer::Read(string* s, const char* tag)
	{
	char* cstr;
	int len;
	if ( format->Read(&cstr, &len, tag) )
		{
		s->assign(cstr, len);
		delete [] cstr;
		return true;
		}
	else
		return false;
	}

bool Serializer::StartSerialization(SerialInfo* info, const char* descr,
					char tag)
	{
	format->StartWrite();
	assert(current_cache);
	SetErrorDescr(fmt("serializing %s", descr));
	if ( ! Write(tag, "tag") )
		{
		Error(io->Error());
		return false;
		}

	current_cache->Begin(info->new_cache_strategy);
	return true;
	}

bool Serializer::EndSerialization(SerialInfo* info)
	{
	if ( info->chunk )
		{
		if ( ! io->Write(info->chunk) )
			{
			Error(io->Error());
			return false;
			}
		}

	ChunkedIO::Chunk* chunk = new ChunkedIO::Chunk;
	chunk->len = format->EndWrite(&chunk->data);
	chunk->free_func = ChunkedIO::Chunk::free_func_free;

	if ( ! io->Write(chunk) )
		{
		Error(io->Error());
		return false;
		}

	current_cache->End(info->new_cache_strategy);
	return true;
	}

bool Serializer::Serialize(SerialInfo* info, const ID& id)
	{
	if ( info->cont.NewInstance() )
		{
		if ( ! (id.IsGlobal() || id.IsEnumConst()) )
			{
			Error("non-global identifiers cannot be serialized");
			return false;
			}

		if ( ! StartSerialization(info, "ID", 'i') )
			return false;
		}

	info->cont.SaveContext();
	bool result = id.Serialize(info);
	info->cont.RestoreContext();

	if ( ! result )
		{
		Error("failed");
		return false;
		}

	if ( info->cont.ChildSuspended() )
		return true;

	WriteSeparator();
	return EndSerialization(info);
	}

bool Serializer::Serialize(SerialInfo* info, const char* func, val_list* args)
	{
	DisableSuspend suspend(info);

	if ( ! StartSerialization(info, "call", 'e') )
		return false;

	WriteOpenTag("call");
	int a = args->length();
	Write(func, "name");
	Write(network_time, "time");
	Write(a, "len");

	loop_over_list(*args, i)
		{
		if ( ! (*args)[i]->Serialize(info) )
			{
			Error("failed");
			return false;
			}
		}

	WriteCloseTag("call");
	WriteSeparator();

	return EndSerialization(info);
	}

bool Serializer::Serialize(SerialInfo* info, const StateAccess& s)
	{
	DisableSuspend suspend(info);

	if ( ! StartSerialization(info, "state access", 's') )
		return false;

	if ( ! s.Serialize(info) )
		{
		Error("failed");
		return false;
		}

	return EndSerialization(info);
	}

bool Serializer::Serialize(SerialInfo* info, const Timer& t)
	{
	DisableSuspend suspend(info);

	if ( ! StartSerialization(info, "timer", 't') )
		return false;

	if ( ! t.Serialize(info) )
		{
		Error("failed");
		return false;
		}

	return EndSerialization(info);
	}

bool Serializer::Serialize(SerialInfo* info, const Connection& c)
	{
	DisableSuspend suspend(info);

	if ( ! StartSerialization(info, "connection", 'c') )
		return false;

	if ( ! c.Serialize(info) )
		{
		Error("failed");
		return false;
		}

	return EndSerialization(info);
	}

bool Serializer::Serialize(SerialInfo* info, const Packet& p)
	{
	DisableSuspend suspend(info);

	if ( ! StartSerialization(info, "packet", 'p') )
		return false;

	if ( ! p.Serialize(info) )
		{
		Error("failed");
		return false;
		}

	return EndSerialization(info);
	}

int Serializer::Unserialize(UnserialInfo* info, bool block)
	{
	assert(current_cache);

	SetErrorDescr("unserializing");

	current_cache->Begin(info->new_cache_strategy);

	ChunkedIO::Chunk* chunk = info->chunk;

	while ( ! chunk )
		{
		if ( ! io->Read(&chunk) )
			{
			if ( io->Eof() )
				return 0;
			Error(io->Error());
			return -1;
			}

		if ( ! chunk && ! block )
			return 0;
		}

	format->StartRead(chunk->data, chunk->len);

	char type;
	if ( ! format->Read(&type, "tag") )
		return -1;

//	DEBUG(fmt("parent: serialization of size %d", );

	bool result;
	switch ( type ) {
	case 'i':
		result = UnserializeID(info);
		break;

	case 'e':
		result = UnserializeCall(info);
		break;

	case 's':
		result = UnserializeStateAccess(info);
		break;

	case 'c':
		result = UnserializeConnection(info);
		break;

	case 't':
		result = UnserializeTimer(info);
		break;

	case 'p':
		result = UnserializePacket(info);
		break;

	default:
		Error(fmt("unknown serialization type %x", (int) type));
		result = false;
	}

	format->EndRead();

	if ( ! info->chunk )
		{ // only delete if we allocated it ourselves
		delete chunk;
		}

	current_cache->End(info->new_cache_strategy);

	return result ? 1 : -1;
	}

bool Serializer::UnserializeID(UnserialInfo* info)
	{
	SetErrorDescr("unserializing ID");

	ID* id = ID::Unserialize(info);

	if ( ! id )
		return false;

	if ( info->print )
		{
		ODesc d;
		d.SetQuotes(true);
		d.SetIncludeStats(true);
		d.SetShort();
		id->DescribeExtended(&d);
		fprintf(info->print, "ID %s\n", d.Description());
		}

	if ( ! info->ignore_callbacks )
		GotID(id, id->ID_Val());
	else
		Unref(id);

	return true;
	}

bool Serializer::UnserializeCall(UnserialInfo* info)
	{
	char* name;
	int len;
	double time;

	if ( ! (UNSERIALIZE_STR(&name, 0) && UNSERIALIZE(&time) && UNSERIALIZE(&len)) )
		return false;

	SetErrorDescr(fmt("unserializing event/function %s", name));

	bool ignore = false;
	FuncType* functype = 0;
	type_list* types = 0;

	ID* id = global_scope()->Lookup(name);

	if ( id )
		{
		if ( id->Type()->Tag() == TYPE_FUNC )
			{
			functype = id->Type()->AsFuncType();
			types = functype->ArgTypes()->Types();
			if ( types->length() != len )
				{
				Error("wrong number of arguments, ignoring");
				ignore = true;
				}
			}
		else
			{
			Error("not a function/event, ignoring");
			ignore = true;
			}
		}
	else
		{
		Error("unknown event/function, ignoring");
		ignore = true;
		}

	ODesc d;
	d.SetQuotes(true);
	d.SetIncludeStats(true);
	d.SetShort();

	val_list* args = new val_list;
	for ( int i = 0; i < len; ++i )
		{
		Val* v = Val::Unserialize(info);

		if ( ! v )
			{
			delete [] name;
			delete_vals(args);
			return false;
			}

		if ( ! ignore )
			{
			if ( v->Type()->Tag() != (*types)[i]->Tag() &&
			     (*types)[i]->Tag() != TYPE_ANY )
				{
				Error("mismatch in argument types; ignoring");
				ignore = true;
				}

			if ( info->print && ! ignore )
				v->Describe(&d);
			}

		args->append(v);
		}

	if ( ! ignore  )
		{
		if ( info->print )
			fprintf(info->print, "%s [%.06f] %s(%s)\n",
				functype->FlavorString().c_str(),
				time, name, types ? d.Description() : "<ignored>");

		switch ( functype->Flavor() ) {

		case FUNC_FLAVOR_EVENT:
			{
			EventHandler* handler = event_registry->Lookup(name);
			assert(handler);

			if ( ! info->ignore_callbacks )
				GotEvent(name, time, handler, args);

			break;
			}

		case FUNC_FLAVOR_FUNCTION:
		case FUNC_FLAVOR_HOOK:
			if ( ! info->ignore_callbacks )
				GotFunctionCall(name, time, id->ID_Val()->AsFunc(), args);
			break;

		default:
			reporter->InternalError("unserialized call for invalid function flavor");
			break;
		}

		if ( info->ignore_callbacks )
			delete_vals(args);
		}
	else
		delete_vals(args);

	delete [] name;

	return true;
	}

bool Serializer::UnserializeStateAccess(UnserialInfo* info)
	{
	SetErrorDescr("unserializing state acess");

	StateAccess* s = StateAccess::Unserialize(info);

	if ( ! s )
		return false;

	if ( info->print )
		{
		ODesc d;
		d.SetQuotes(true);
		d.SetIncludeStats(true);
		d.SetShort();
		s->Describe(&d);
		fprintf(info->print, "State access: %s\n", d.Description());
		}

	if ( ! info->ignore_callbacks )
		GotStateAccess(s);
	else
		delete s;

	return true;
	}

bool Serializer::UnserializeTimer(UnserialInfo* info)
	{
	SetErrorDescr("unserializing timer");

	Timer* t = Timer::Unserialize(info);

	if ( ! t )
		return false;

	if ( info->print )
		{
		ODesc d;
		d.SetQuotes(true);
		d.SetIncludeStats(true);
		d.SetShort();
		t->Describe(&d);
		fprintf(info->print, "Timer: %s\n", d.Description());
		}

	if ( ! info->ignore_callbacks )
		GotTimer(t);

	return true;
	}

bool Serializer::UnserializeConnection(UnserialInfo* info)
	{
	SetErrorDescr("unserializing connection");

	Connection* c = Connection::Unserialize(info);

	if ( ! c )
		return false;

	if ( info->print )
		{
		ODesc d;
		d.SetQuotes(true);
		d.SetIncludeStats(true);
		d.SetShort();
		c->Describe(&d);
		fprintf(info->print, "Connection: %s", d.Description());
		}

	if ( info->install_conns )
		{
		if ( c->IsPersistent() && c->Key() )
			persistence_serializer->Register(c);
		Ref(c);
		sessions->Insert(c);
		}
	else
		// We finish the connection here because it's not part
		// of the standard processing and most likely to be
		// discarded pretty soon.
		// Without the Done(), some cleanup may not take place.
		c->Done();

	if ( ! info->ignore_callbacks )
		GotConnection(c);
	else
		Unref(c);

	return true;
	}

bool Serializer::UnserializePacket(UnserialInfo* info)
	{
	SetErrorDescr("unserializing packet");

	Packet* p = Packet::Unserialize(info);

	if ( ! p )
		return false;

	if ( info->print )
		{
		ODesc d;
		d.SetQuotes(true);
		d.SetIncludeStats(true);
		d.SetShort();
		p->Describe(&d);
		fprintf(info->print, "Packet: %s", d.Description());
		}

	if ( ! info->ignore_callbacks )
		GotPacket(p);
	else
		delete p;

	return true;
	}

void Serializer::Error(const char* str)
	{
	char buffer[1024];
	safe_snprintf(buffer, sizeof(buffer), "%s%s%s",
		      error_descr ? error_descr : "", error_descr ? ": " : "", str);
	ReportError(buffer);
	}

void Serializer::Warning(const char* str)
	{
	// We ignore these as there's no good place to report them.
	}

SerializationCache::SerializationCache(unsigned int arg_max_cache_size)
	{
	max_cache_size = arg_max_cache_size;
	next_id = 1;
	cache_stable.head = cache_stable.tail = 0;
	cache_unstable.head = cache_unstable.tail = 0;
	cache_stable.size = cache_unstable.size = 0;
	}

SerializationCache::~SerializationCache()
	{
	Clear();
	}

SerializationCache::PermanentID
SerializationCache::Register(const SerialObj* obj, PermanentID pid,
				bool new_cache_strategy)
	{
	if ( pid == NONE )
		pid = next_id++;

	PIDMap::iterator i = pid_map.find(pid);
	assert(i == pid_map.end());

	CacheList* cache =
		(new_cache_strategy && obj->IsCacheStable()) ?
			&cache_stable : &cache_unstable;

	CacheEntry* entry = new CacheEntry;
	entry->obj.serial = obj;
	entry->is_bro_obj = obj->IsBroObj();
	entry->pid = pid;
	entry->tid = obj->GetTID()->Value();
	entry->time = SerialObj::GetTimeCounter();
	entry->prev = cache->tail;
	entry->next = 0;
	entry->cache = cache;
	entry->stype = obj->GetSerialType();

	if ( cache->tail )
		cache->tail->next = entry;
	if ( ! cache->head )
		cache->head = entry;

	cache->tail = entry;
	++(cache->size);

	// This is a bit weird. If the TID is already contained in the map (i.e.
	// we're re-registering), TIDMap::insert() will *not* override the old
	// entry but set the bool to false and return it.
	pair<TIDMap::iterator, bool> old = tid_map.insert(TIDMap::value_type(entry->tid, entry));
	if ( ! old.second )
		{
		// Already existed.
		old.first->second->tid = 0;	// invalidate
		old.first->second = entry;	// replace
		}

	pid_map.insert(PIDMap::value_type(pid, entry));

	if ( entry->is_bro_obj )
		Ref(const_cast<BroObj*>(entry->obj.bro));
	else
		{
		// Make sure it goes into unstable.
		assert(! obj->IsCacheStable());

		volatiles.push_back(entry);
		}

	return entry->pid;
	}

void SerializationCache::UnlinkEntry(CacheEntry* e)
	{
	assert(e);

	// Remove from double-linked list.
	if ( e == e->cache->head )
		{
		e->cache->head = e->next;
		if ( e->cache->head )
			e->cache->head->prev = 0;
		}
	else
		e->prev->next = e->next;

	if ( e == e->cache->tail )
		{
		e->cache->tail = e->prev;
		if ( e->cache->tail )
			e->cache->tail->next = 0;
		}
	else
		e->next->prev = e->prev;

	e->prev = e->next = 0;
	}

void SerializationCache::RemoveEntry(CacheEntry* e)
	{
	assert(e);
	UnlinkEntry(e);

	if ( e->tid )
		tid_map.erase(e->tid);

	pid_map.erase(e->pid);

	if ( e->is_bro_obj )
		Unref(const_cast<BroObj*>(e->obj.bro));

	e->obj.serial = 0; // for debugging
	--(e->cache->size);
	delete e;
	}

void SerializationCache::MoveEntryToTail(CacheEntry* e)
	{
	assert(e);
	UnlinkEntry(e);
	e->prev = e->cache->tail;
	e->next = 0;

	if ( e->cache->tail )
		e->cache->tail->next = e;
	if ( ! e->cache->head )
		e->cache->head = e;

	e->cache->tail = e;
	}

void SerializationCache::Clear()
	{
	tid_map.clear();
	pid_map.clear();
	volatiles.clear();

	while ( cache_stable.head )
		RemoveEntry(cache_stable.head);

	while ( cache_unstable.head )
		RemoveEntry(cache_unstable.head);

	assert(cache_stable.size == 0);
	assert(cache_unstable.size == 0);
	}

void SerializationCache::End(bool new_cache_strategy)
	{
	// Remove objects not-derived from BroObj (they aren't ref'counted
	// so it's not safe to keep them).
	for ( VolatileList::iterator i = volatiles.begin();
	      i != volatiles.end(); i++ )
		{
		assert(*i);
		RemoveEntry(*i);
		}

	volatiles.clear();

	if ( new_cache_strategy )
		{
		while ( max_cache_size && cache_stable.head &&
				cache_stable.size > max_cache_size )
			RemoveEntry(cache_stable.head);

		while ( max_cache_size && cache_unstable.head &&
				cache_unstable.size > max_cache_size )
			RemoveEntry(cache_unstable.head);
		}

	else
		{
		while ( max_cache_size && pid_map.size() > max_cache_size )
			RemoveEntry(cache_unstable.head);
		}
	}

FileSerializer::FileSerializer(SerializationFormat* format)
: Serializer(format), cache(100)
	{
	file = 0;
	fd = -1;
	io = 0;
	SetCache(&cache);
	}

FileSerializer::~FileSerializer()
	{
	if ( io )
		io->Flush();

	delete [] file;

	if ( io )
		delete io;  // destructor will call close() on fd
	else if ( fd >= 0 )
		safe_close(fd);
	}

bool FileSerializer::Open(const char* file, bool pure)
	{
	if ( ! OpenFile(file, false) )
		return false;

	if ( pure )
		io->MakePure();

	if ( ! PrepareForWriting() )
		return false;

	return true;
	}

bool FileSerializer::Close()
	{
	CloseFile();
	return true;
	}

bool FileSerializer::OpenFile(const char* arg_file, bool readonly, bool should_exist)
	{
	CloseFile();

	cache.Clear();

	file = copy_string(arg_file);
	fd = open(file, readonly ? O_RDONLY : O_WRONLY | O_CREAT | O_TRUNC, 0600);

	if ( fd < 0 )
		{
		if ( readonly && errno == ENOENT )
			{
			// Only an error if we expect to exist.
			if ( should_exist )
				{
				Error(fmt("%s does not exist", file));
				return false;
				}

			CloseFile();
			return true;
			}

		Error(fmt("can't open file %s for %s: %s",
				file, (readonly ? "reading" : "writing"),
				strerror(errno)));
		return false;
		}

	io = new ChunkedIOFd(fd, "file");

	return io != 0;
	}

void FileSerializer::CloseFile()
	{
	if ( io )
		io->Flush();

	if ( fd >= 0 && ! io ) // destructor of io calls close() on fd
		safe_close(fd);
	fd = -1;

	delete [] file;
	file = 0;

	delete io;
	io = 0;

	cache.Clear();
	}

bool FileSerializer::PrepareForWriting()
	{
	if ( ! io->IsPure() )
		{
		// Write file header.
		uint32 magic = htonl(MAGIC);
		uint16 version = htons(DATA_FORMAT_VERSION);
		uint32 time = htonl(uint32(::time(0)));

		if ( write(fd, &magic, sizeof(magic)) != sizeof(magic ) ||
		     write(fd, &version, sizeof(version)) != sizeof(version) ||
		     write(fd, &time, sizeof(time)) != sizeof(time))
			{
			Error(fmt("can't write file header to %s: %s",
					file, strerror(errno)));
			return false;
			}
		}

	return true;
	}

bool FileSerializer::ReadHeader(UnserialInfo* info)
	{
	uint32 magic;
	uint16 version;
	uint32 time;

	if ( read(fd, &magic, sizeof(magic)) != sizeof(magic ) ||
	     read(fd, &version, sizeof(version)) != sizeof(version) ||
	     read(fd, &time, sizeof(time)) != sizeof(time) )
		{
		Error(fmt("can't read file header from %s: %s",
				file, strerror(errno)));
		return false;
		}

	version = ntohs(version);
	time = ntohl(time);

	if ( info && info->print )
		{
		time_t teatime = (time_t) time;
		fprintf(stderr, "Date: %s", ctime(&teatime));
		}

	if ( magic != htonl(MAGIC) )
		{
		Error(fmt("%s is not a bro state file", file));
		CloseFile();
		return false;
		}

	if ( version != DATA_FORMAT_VERSION )
		{
		Error(fmt("wrong data format, expected version %d but got version %d", DATA_FORMAT_VERSION, version));
		CloseFile();
		return false;
		}

	return true;
	}

bool FileSerializer::Read(UnserialInfo* info, const char* file, bool header)
	{
	if ( ! OpenFile(file, true, info->print) )
		return false;

	// fprintf( stderr, "Reading %s\n", file );

	if ( fd < 0 )
		// Not existent, but that's ok.
		return true;

	if ( header && ! ReadHeader(info) )
		return false;

	int i;
	while ( (i = Unserialize(info, true)) > 0 )
		;

	CloseFile();

	return i == 0;
	}

void FileSerializer::ReportError(const char* str)
	{
	reporter->Error("%s", str);
	}

void FileSerializer::GotID(ID* id, Val* val)
	{
	// Do nothing.
	Unref(id);
	}

void FileSerializer::GotStateAccess(StateAccess* s)
	{
	delete s;
	}

void FileSerializer::GotEvent(const char* name, double time,
				EventHandlerPtr event, val_list* args)
	{
	// Do nothing.
	delete_vals(args);
	}

void FileSerializer::GotFunctionCall(const char* name, double time,
				Func* func, val_list* args)
	{
	// Do nothing.
	delete_vals(args);
	}

void FileSerializer::GotTimer(Timer* t)
	{
	// Do nothing.
	delete t;
	}

void FileSerializer::GotConnection(Connection* c)
	{
	// Do nothing.
	Unref(c);
	}

void FileSerializer::GotPacket(Packet* p)
	{
	// Do nothing.
	delete p;
	}

ConversionSerializer::ConversionSerializer(SerializationFormat* in,
						SerializationFormat* out)
: FileSerializer(in)
	{
	serout = new FileSerializer(out);
	}

ConversionSerializer::~ConversionSerializer()
	{
	delete serout;
	}

bool ConversionSerializer::Convert(const char* file_in, const char* file_out)
	{
	reporter->InternalError("Error: Printing as XML is broken.");

	if ( ! serout->Open(file_out, true) )
		return false;

	UnserialInfo info_in(this);
	if ( ! Read(&info_in, file_in) )
		return false;

	if ( ! serout->Close() )
		return false;

	return true;
	}

void ConversionSerializer::GotEvent(const char* name, double time,
					EventHandlerPtr event, val_list* args)
	{
	SerialInfo info(serout);
	serout->Serialize(&info, name, args);
	delete_vals(args);
	}

void ConversionSerializer::GotFunctionCall(const char* name, double time,
					Func* func, val_list* args)
	{
	SerialInfo info(serout);
	serout->Serialize(&info, name, args);
	delete_vals(args);
	}

void ConversionSerializer::GotID(ID* id, Val* val)
	{
	reporter->Warning("ConversionSerializer::GotID not implemented");
	Unref(id);
	}

void ConversionSerializer::GotStateAccess(StateAccess* s)
	{
	reporter->Warning("ConversionSerializer::GotID not implemented");
	delete s;
	}

void ConversionSerializer::GotPacket(Packet* p)
	{
	reporter->Warning("ConversionSerializer::GotPacket not implemented");
	delete p;
	}

EventPlayer::EventPlayer(const char* file)
    : stream_time(), replay_time(), ne_time(), ne_handler(), ne_args()
	{
	if ( ! OpenFile(file, true) || fd < 0 )
		Error(fmt("event replayer: cannot open %s", file));

	if ( ReadHeader() )
		io_sources.Register(this);
	}

EventPlayer::~EventPlayer()
	{
	CloseFile();
	}

void EventPlayer::GotEvent(const char* name, double time,
		EventHandlerPtr event, val_list* args)
	{
	ne_time = time;
	ne_handler = event;
	ne_args = args;
	}

void EventPlayer::GotFunctionCall(const char* name, double time,
		Func* func, val_list* args)
	{
	// We don't replay function calls.
	}

void EventPlayer::GetFds(int* read, int* write, int* except)
	{
	*read = fd;
	}

double EventPlayer::NextTimestamp(double* local_network_time)
	{
	if ( ne_time )
		return ne_time;

	if ( ! io )
		return 0;

	// Read next event if we don't have one waiting.
	if ( ! ne_time )
		{
		UnserialInfo info(this);
		Unserialize(&info);
		closed = io->Eof();
		}

	if ( ! ne_time )
		return 0;

	if ( ! network_time )
		{
		// Network time not initialized yet.
		stream_time = replay_time = ne_time;
		return ne_time;
		}

	if ( ! stream_time )
		{
		// Init base times.
		stream_time = ne_time;
		replay_time = network_time;
		}

	// Scale time.
	ne_time = ne_time - stream_time + network_time;
	return ne_time;
	}

void EventPlayer::Process()
	{
	if ( ! (io && ne_time) )
		return;

	Event* event = new Event(ne_handler, ne_args);
	mgr.Dispatch(event);

	ne_time = 0;
	}

void Packet::Describe(ODesc* d) const
	{
	const IP_Hdr ip = IP();
	d->Add(ip.SrcAddr());
	d->Add("->");
	d->Add(ip.DstAddr());
	}

bool Packet::Serialize(SerialInfo* info) const
	{
	return SERIALIZE(uint32(hdr->ts.tv_sec)) &&
		SERIALIZE(uint32(hdr->ts.tv_usec)) &&
		SERIALIZE(uint32(hdr->len)) &&
		SERIALIZE(link_type) &&
		info->s->Write(tag.c_str(), 0, "tag") &&
		info->s->Write((const char*) pkt, hdr->caplen, "data");
	}

static BroFile* profiling_output = 0;

#ifdef DEBUG
static PktDumper* dump = 0;
#endif

Packet* Packet::Unserialize(UnserialInfo* info)
	{
	Packet* p = new Packet("", true);
	pcap_pkthdr* hdr = new pcap_pkthdr;

	uint32 tv_sec, tv_usec, len;

	if ( ! (UNSERIALIZE(&tv_sec) &&
		UNSERIALIZE(&tv_usec) &&
		UNSERIALIZE(&len) &&
		UNSERIALIZE(&p->link_type)) )
		{
		delete p;
		delete hdr;
		return 0;
		}

	hdr->ts.tv_sec = tv_sec;
	hdr->ts.tv_usec = tv_usec;
	hdr->len = len;

	char* tag;
	if ( ! info->s->Read((char**) &tag, 0, "tag") )
		{
		delete p;
		delete hdr;
		return 0;
		}

	char* pkt;
	int caplen;
	if ( ! info->s->Read((char**) &pkt, &caplen, "data") )
		{
		delete p;
		delete hdr;
		delete [] tag;
		return 0;
		}

	hdr->caplen = uint32(caplen);
	p->hdr = hdr;
	p->pkt = (u_char*) pkt;
	p->tag = tag;
	p->hdr_size = get_link_header_size(p->link_type);

	delete [] tag;

	// For the global timer manager, we take the global network_time as the
	// packet's timestamp for feeding it into our packet loop.
	if ( p->tag == "" )
		p->time = timer_mgr->Time();
	else
		p->time = p->hdr->ts.tv_sec + double(p->hdr->ts.tv_usec) / 1e6;

	if ( time_machine_profiling )
		{
		if ( ! profiling_output )
			profiling_output =
				new BroFile("tm-prof.packets.log", "w");

		profiling_output->Write(fmt("%.6f %s %d\n", current_time(),
			(p->tag != "" ? p->tag.c_str() : "-"), hdr->len));
		}

#ifdef DEBUG
	if ( debug_logger.IsEnabled(DBG_TM) )
		{
		if ( ! dump )
			dump = new PktDumper("tm.pcap");

		dump->Dump(p->hdr, p->pkt);
		}
#endif

	return p;
	}
