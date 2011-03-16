
#include "LogMgr.h"
#include "Event.h"
#include "EventHandler.h"
#include "NetVar.h"
#include "Net.h"

#include "LogWriterAscii.h"

struct LogWriterDefinition {
    bro_int_t type;	// The type.
	const char *name;	// Descriptive name for error messages.
	bool (*init)();	// An optional one-time initialization function.
	LogWriter* (*factory)();	// A factory function creating instances.
};

LogWriterDefinition log_writers[] = {
	{ BifEnum::Log::WRITER_ASCII, "Ascii", 0, LogWriterAscii::Instantiate },

	// End marker.
	{ BifEnum::Log::WRITER_DEFAULT, "None", 0, (LogWriter* (*)())0 }
};

struct LogMgr::Filter {
	string name;
	EnumVal* id;
	Func* pred;
	Func* path_func;
	string path;
	Val* path_val;
	EnumVal* writer;
	bool local;
	bool remote;

	int num_fields;
	LogField** fields;
	vector<list<int> > indices; // List of record indices per field.

	~Filter();
};

struct LogMgr::WriterInfo {
	EnumVal* type;
	double open_time;
	Timer* rotation_timer;
	LogWriter *writer;
	};

struct LogMgr::Stream {
 	EnumVal* id;
	bool enabled;
	string name;
	RecordType* columns;
	EventHandlerPtr event;
	list<Filter*> filters;

	typedef pair<int, string> WriterPathPair;

	typedef map<WriterPathPair, WriterInfo*> WriterMap;

	WriterMap writers; // Writers indexed by id/path pair.

	~Stream();
	};

LogVal::~LogVal()
	{
	if ( (type == TYPE_ENUM || type == TYPE_STRING) && present )
		delete val.string_val;

	if ( type == TYPE_TABLE && present )
		{
		for ( int i = 0; i < val.set_val.size; i++ )
			delete val.set_val.vals[i];

		delete [] val.set_val.vals;
		}
	}

bool LogVal::IsCompatibleType(BroType* t, bool atomic_only)
	{
	if ( ! t )
		return false;

	switch ( t->Tag() )	{
	case TYPE_BOOL:
	case TYPE_INT:
	case TYPE_COUNT:
	case TYPE_COUNTER:
	case TYPE_PORT:
	case TYPE_SUBNET:
	case TYPE_NET:
	case TYPE_ADDR:
	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
	case TYPE_ENUM:
	case TYPE_STRING:
		return true;

	case TYPE_RECORD:
		return ! atomic_only;

	case TYPE_TABLE:
		{
		if ( atomic_only )
			return false;

		if ( ! t->IsSet() )
			return false;

		return IsCompatibleType(t->AsSetType()->Indices()->PureType());
		}

	default:
		return false;
	}

	return false;
	}
   
bool LogVal::Read(SerializationFormat* fmt)
	{
	int ty;

	if ( ! (fmt->Read(&ty, "type") && fmt->Read(&present, "present")) )
		return false;

	type = (TypeTag)(ty);

	if ( ! present )
		return true;

	switch ( type ) {
	case TYPE_BOOL:
	case TYPE_INT:
		return fmt->Read(&val.int_val, "int");

	case TYPE_COUNT:
	case TYPE_COUNTER:
	case TYPE_PORT:
		return fmt->Read(&val.uint_val, "uint");

	case TYPE_SUBNET:
		{
		uint32 net[4];
		if ( ! (fmt->Read(&net[0], "net0")
			&& fmt->Read(&net[1], "net1")
			&& fmt->Read(&net[2], "net2")
			&& fmt->Read(&net[3], "net3")
			&& fmt->Read(&val.subnet_val.width, "width")) )
			return false;

#ifdef BROv6
		val.subnet_val.net[0] = net[0];
		val.subnet_val.net[1] = net[1];
		val.subnet_val.net[2] = net[2];
		val.subnet_val.net[3] = net[3];
#else
		val.subnet_val.net = net[0];
#endif
		return true;
		}

	case TYPE_NET:
	case TYPE_ADDR:
		{
		uint32 addr[4];
		if ( ! (fmt->Read(&addr[0], "addr0")
			&& fmt->Read(&addr[1], "addr1")
			&& fmt->Read(&addr[2], "addr2")
			&& fmt->Read(&addr[3], "addr3")) )
			return false;

#ifdef BROv6
		val.addr_val[0] = addr[0];
		val.addr_val[1] = addr[1];
		val.addr_val[2] = addr[2];
		val.addr_val[3] = addr[3];
#else
		val.addr_val = addr[0];
#endif
		return true;
		}

	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
		return fmt->Read(&val.double_val, "double");

	case TYPE_ENUM:
	case TYPE_STRING:
		{
		val.string_val = new string;
		return fmt->Read(val.string_val, "string");
		}

	case TYPE_TABLE:
		{
		if ( ! fmt->Read(&val.set_val.size, "set_size") )
			return false;

		val.set_val.vals = new LogVal* [val.set_val.size];

		for ( int i = 0; i < val.set_val.size; ++i )
			{
			val.set_val.vals[i] = new LogVal;
			if ( ! val.set_val.vals[i]->Read(fmt) )
				return false;
			}

		return true;
		}

	default:
		internal_error(::fmt("unsupported type %s in LogVal::Write", type_name(type)));
	}

	return false;
	}

bool LogVal::Write(SerializationFormat* fmt) const
	{
	if ( ! (fmt->Write((int)type, "type") && fmt->Write(present, "present")) )
		return false;

	if ( ! present )
		return true;

	switch ( type ) {
	case TYPE_BOOL:
	case TYPE_INT:
		return fmt->Write(val.int_val, "int");

	case TYPE_COUNT:
	case TYPE_COUNTER:
	case TYPE_PORT:
		return fmt->Write(val.uint_val, "uint");

	case TYPE_SUBNET:
		{
#ifdef BROv6
		uint32* net = val.subnet_val;
#else
		uint32 net[4];
		net[0] = val.subnet_val.net;
		net[1] = net[2] = net[3] = 0;
#endif
		return fmt->Write(net[0], "net0")
			&& fmt->Write(net[1], "net1")
			&& fmt->Write(net[2], "net2")
			&& fmt->Write(net[3], "net3")
			&& fmt->Write(val.subnet_val.width, "width");
		}

	case TYPE_NET:
	case TYPE_ADDR:
		{
#ifdef BROv6
		uint32* addr = val.addr_val;
#else
		uint32 addr[4];
		addr[0] = val.addr_val;
		addr[1] = addr[2] = addr[3] = 0;
#endif
		return fmt->Write(addr[0], "addr0")
			&& fmt->Write(addr[1], "addr1")
			&& fmt->Write(addr[2], "addr2")
			&& fmt->Write(addr[3], "addr3");
		}

	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
		return fmt->Write(val.double_val, "double");

	case TYPE_ENUM:
	case TYPE_STRING:
		return fmt->Write(*val.string_val, "string");

	case TYPE_TABLE:
		{
		if ( ! fmt->Write(val.set_val.size, "set_size") )
			return false;

		for ( int i = 0; i < val.set_val.size; ++i )
			{
			if ( ! val.set_val.vals[i]->Write(fmt) )
				return false;
			}

		return true;
		}

	default:
		internal_error(::fmt("unsupported type %s in LogVal::REad", type_name(type)));
	}

	return false;
	}

LogMgr::Filter::~Filter()
	{
	for ( int i = 0; i < num_fields; ++i )
		delete fields[i];

	Unref(path_val);
	}

LogMgr::Stream::~Stream()
	{
	Unref(columns);

	for ( WriterMap::iterator i = writers.begin(); i != writers.end(); i++ )
		{
		WriterInfo* winfo = i->second;

		if ( winfo->rotation_timer )
			timer_mgr->Cancel(winfo->rotation_timer);

		Unref(winfo->type);
		delete winfo->writer;
		delete i->second;
		}

	for ( list<Filter*>::iterator f = filters.begin(); f != filters.end(); ++f )
		delete *f;
	}

LogMgr::LogMgr()
	{
	}

LogMgr::~LogMgr()
	{
	for ( vector<Stream *>::iterator s = streams.begin(); s != streams.end(); ++s )
		delete *s;
	}

LogMgr::Stream* LogMgr::FindStream(EnumVal* id)
	{
	unsigned int idx = id->AsEnum();

	if ( idx >= streams.size() || ! streams[idx] )
		{
		// run_time(fmt("unknown log stream (%d)", id->AsEnum()));
		return 0;
		}

	return streams[idx];
	}

void LogMgr::RemoveDisabledWriters(Stream* stream)
	{
	list<Stream::WriterPathPair> disabled;

	for ( Stream::WriterMap::iterator j = stream->writers.begin(); j != stream->writers.end(); j++ )
		{
		if ( j->second->writer->Disabled() )
			{
			delete j->second;
			disabled.push_back(j->first);
			}
		}

	for ( list<Stream::WriterPathPair>::iterator j = disabled.begin(); j != disabled.end(); j++ )
		stream->writers.erase(*j);
	}

bool LogMgr::CreateStream(EnumVal* id, RecordVal* sval)
	{
	RecordType* rtype = sval->Type()->AsRecordType();

	if ( ! same_type(rtype, BifType::Record::Log::Stream, 0) )
		{
		run_time("sval argument not of right type");
		return false;
		}

	RecordType* columns = sval->Lookup(rtype->FieldOffset("columns"))->AsType()->AsTypeType()->Type()->AsRecordType();

	for ( int i = 0; i < columns->NumFields(); i++ )
		{
		if ( ! LogVal::IsCompatibleType(columns->FieldType(i)) )
			{
			run_time("type of field '%s' is not support for logging output", columns->FieldName(i));
			return false;
			}
		}

	Val* event_val = sval->Lookup(rtype->FieldOffset("ev"));
	Func* event = event_val ? event_val->AsFunc() : 0;

	if ( event )
		{
		// Make sure the event prototyped as expected.
		FuncType* etype = event->FType()->AsFuncType();

		if ( ! etype->IsEvent() )
			{
			run_time("stream event is a function, not an event");
			return false;
			}

		const type_list* args = etype->ArgTypes()->Types();

		if ( args->length() != 1 )
			{
			run_time("stream event must take a single argument");
			return false;
			}

		if ( ! same_type((*args)[0], columns) )
			{
			run_time("stream event's argument type does not match column record type");
			return new Val(0, TYPE_BOOL);
			}
		}

	// Make sure the vector has an entries for all streams up to the one
	// given.

	unsigned int idx = id->AsEnum();

	while ( idx >= streams.size() )
		streams.push_back(0);

	if ( streams[idx] )
		// We already know this one, delete the previous definition.
		delete streams[idx];

	// Create new stream.
	streams[idx] = new Stream;
	streams[idx]->id = id->Ref()->AsEnumVal();
	streams[idx]->enabled = true;
	streams[idx]->name = id->Type()->AsEnumType()->Lookup(idx);
	streams[idx]->event = event ? event_registry->Lookup(event->GetID()->Name()) : 0;
	streams[idx]->columns = columns->Ref()->AsRecordType();

	DBG_LOG(DBG_LOGGING, "Created new logging stream '%s', raising event %s", streams[idx]->name.c_str(), event ? streams[idx]->event->Name() : "<none>");

	return true;
	}

bool LogMgr::EnableStream(EnumVal* id)
	{
	Stream* stream = FindStream(id);
	if ( ! stream )
		return false;

	if ( stream->enabled )
		return true;

	stream->enabled = true;

	DBG_LOG(DBG_LOGGING, "Reenabled logging stream '%s'", stream->name.c_str());
	return true;
	}

bool LogMgr::DisableStream(EnumVal* id)
	{
	Stream* stream = FindStream(id);
	if ( ! stream )
		return false;

	if ( ! stream->enabled )
		return true;

	stream->enabled = false;

	DBG_LOG(DBG_LOGGING, "Disabled logging stream '%s'", stream->name.c_str());
	return true;
	}

// Helper for recursive record field unrolling.
bool LogMgr::TraverseRecord(Filter* filter, RecordType* rt, TableVal* include, TableVal* exclude, string path, list<int> indices)
	{
	for ( int i = 0; i < rt->NumFields(); ++i )
		{
		BroType* t = rt->FieldType(i);

		list<int> new_indices = indices;
		new_indices.push_back(i);

		// Build path name.
		string new_path;
	   	if ( ! path.size() )
			new_path = rt->FieldName(i);
		else
			new_path = path + "." + rt->FieldName(i);

		StringVal* new_path_val = new StringVal(path.c_str());

		if ( t->InternalType() == TYPE_INTERNAL_OTHER )
			{
			if ( t->Tag() == TYPE_RECORD )
				{
				// Recurse.
				if ( ! TraverseRecord(filter, t->AsRecordType(), include, exclude, new_path, new_indices) )
					return false;

				continue;
				}
			else if ( t->Tag() == TYPE_TABLE && t->AsTableType()->IsSet() )
				{
				// That's ok, handle it with all the other types below.
				}

			else {
				run_time("unsupported field type for log column");
				return false;
				}
			}

		// If include fields are specified, only include if explicitly listed.
		if ( include )
			{
			if ( ! include->Lookup(new_path_val) )
				return true;
			}

		// If exclude fields are specified, do not only include if listed.
		if ( exclude )
			{
			if ( exclude->Lookup(new_path_val) )
				return true;
			}

		// Alright, we want this field.

		filter->indices.push_back(new_indices);
		filter->fields = (LogField**) realloc(filter->fields, sizeof(LogField) * ++filter->num_fields);
		if ( ! filter->fields )
			{
			run_time("out of memory in add_filter");
			return false;
			}

		LogField* field = new LogField();
		field->name = new_path;
		field->type = t->Tag();
		filter->fields[filter->num_fields - 1] = field;
		}

	return true;
	}

bool LogMgr::AddFilter(EnumVal* id, RecordVal* fval)
	{
	RecordType* rtype = fval->Type()->AsRecordType();

	if ( ! same_type(rtype, BifType::Record::Log::Filter, 0) )
		{
		run_time("filter argument not of right type");
		return false;
		}

	Stream* stream = FindStream(id);
	if ( ! stream )
		return false;

	// Find the right writer type.
	int idx = rtype->FieldOffset("writer");
	EnumVal* writer = fval->LookupWithDefault(idx)->AsEnumVal();

	// Create a new Filter instance.

	Val* name = fval->LookupWithDefault(rtype->FieldOffset("name"));
	Val* pred = fval->LookupWithDefault(rtype->FieldOffset("pred"));
	Val* path_func = fval->LookupWithDefault(rtype->FieldOffset("path_func"));
	Val* log_local = fval->LookupWithDefault(rtype->FieldOffset("log_local"));
	Val* log_remote = fval->LookupWithDefault(rtype->FieldOffset("log_remote"));

	Filter* filter = new Filter;
	filter->name = name->AsString()->CheckString();
	filter->id = id->Ref()->AsEnumVal();
	filter->pred = pred ? pred->AsFunc() : 0;
	filter->path_func = path_func ? path_func->AsFunc() : 0;
	filter->writer = writer->Ref()->AsEnumVal();
	filter->local = log_local->AsBool();
	filter->remote = log_remote->AsBool();

	Unref(name);
	Unref(pred);
	Unref(path_func);
	Unref(log_local);
	Unref(log_remote);

	// TODO: Check that the predciate is of the right type.

	// Build the list of fields that the filter wants included, including
	// potentially rolling out fields.
	Val* include = fval->Lookup(rtype->FieldOffset("include"));
	Val* exclude = fval->Lookup(rtype->FieldOffset("exclude"));

	filter->num_fields = 0;
	filter->fields = 0;
	if ( ! TraverseRecord(filter, stream->columns, include ? include->AsTableVal() : 0, exclude ? exclude->AsTableVal() : 0, "", list<int>()) )
		return false;

	// Get the path for the filter.
	Val* path_val = fval->Lookup(rtype->FieldOffset("path"));

	if ( path_val )
		{
		filter->path = path_val->AsString()->CheckString();
		filter->path_val = path_val->Ref();
		}

	else
		{
		// If no path is given, use the Stream ID's namespace as the default
		// if it has one, and it ID itself otherwise.
		const char* s = stream->name.c_str();
		const char* e = strstr(s, "::");

		if ( ! e )
			e = s + strlen(s);

		string path(s, e);
		std::transform(path.begin(), path.end(), path.begin(), ::tolower);

		filter->path = path;
		filter->path_val = new StringVal(path.c_str());
		}

	// Remove any filter with the same name we might already have.
	RemoveFilter(id, filter->name);

	// Add the new one.
	stream->filters.push_back(filter);

#ifdef DEBUG
	ODesc desc;
	writer->Describe(&desc);

	DBG_LOG(DBG_LOGGING, "Created new filter '%s' for stream '%s'", filter->name.c_str(), stream->name.c_str());
	DBG_LOG(DBG_LOGGING, "   writer    : %s", desc.Description());
	DBG_LOG(DBG_LOGGING, "   path      : %s", filter->path.c_str());
	DBG_LOG(DBG_LOGGING, "   path_func : %s", (filter->path_func ? "set" : "not set"));
	DBG_LOG(DBG_LOGGING, "   pred      : %s", (filter->pred ? "set" : "not set"));

	for ( int i = 0; i < filter->num_fields; i++ )
		{
		LogField* field = filter->fields[i];
		DBG_LOG(DBG_LOGGING, "   field %10s: %s", field->name.c_str(), type_name(field->type));
		}
#endif

	return true;
	}

bool LogMgr::RemoveFilter(EnumVal* id, StringVal* name)
	{
	return RemoveFilter(id, name->AsString()->CheckString());
	}

bool LogMgr::RemoveFilter(EnumVal* id, string name)
	{
	Stream* stream = FindStream(id);
	if ( ! stream )
		return false;

	for ( list<Filter*>::iterator i = stream->filters.begin(); i != stream->filters.end(); ++i )
		{
		if ( (*i)->name == name )
			{
			Filter* filter = *i;
			stream->filters.erase(i);
			DBG_LOG(DBG_LOGGING, "Removed filter '%s' from stream '%s'", filter->name.c_str(), stream->name.c_str());
			delete filter;
			return true;
			}
		}

	// If we don't find the filter, we don't treat that as an error.
	DBG_LOG(DBG_LOGGING, "Did not find filter '%s' for removing from stream '%s'", name.c_str(), stream->name.c_str());
	return true;
	}

bool LogMgr::Write(EnumVal* id, RecordVal* columns)
	{
	bool error = false;

	Stream* stream = FindStream(id);
	if ( ! stream )
		return false;

	if ( ! stream->enabled )
		return true;

	columns = columns->CoerceTo(stream->columns);

	if ( ! columns )
		{
		run_time("incompatible log record type");
		return false;
		}

	// Raise the log event.
	if ( stream->event )
		{
		val_list* vl = new val_list(1);
		vl->append(columns->Ref());
		mgr.QueueEvent(stream->event, vl, SOURCE_LOCAL);
		}

	// Send to each of our filters.
	for ( list<Filter*>::iterator i = stream->filters.begin(); i != stream->filters.end(); ++i )
		{
		Filter* filter = *i;
		string path = filter->path;

		if ( filter->pred )
			{
			// See whether the predicates indicates that we want to log this record.
			val_list vl(1);
			vl.append(columns->Ref());
			Val* v = filter->pred->Call(&vl);
			int result = v->AsBool();
			Unref(v);

			if ( ! result )
				continue;
			}

		if ( filter->path_func )
			{
			val_list vl(2);
			vl.append(id->Ref());
			vl.append(filter->path_val->Ref());
			Val* v = filter->path_func->Call(&vl);

			if ( ! v->Type()->Tag() == TYPE_STRING )
				{
				run_time("path_func did not return string");
				Unref(v);
				return false;
				}

			path = v->AsString()->CheckString();

#ifdef DEBUG
			DBG_LOG(DBG_LOGGING, "Path function for filter '%s' on stream '%s' return '%s'", filter->name.c_str(), stream->name.c_str(), path.c_str());
#endif
			}

		// See if we already have a writer for this path.
		Stream::WriterMap::iterator w = stream->writers.find(Stream::WriterPathPair(filter->writer->AsEnum(), path));

		LogWriter* writer = 0;

		if ( w != stream->writers.end() )
			// We have a writer already.
			writer = w->second->writer;
		else
			{
			// No, need to create one.

			// Copy the fields for LogWriter::Init() as it will take
			// ownership.
			LogField** arg_fields = new LogField*[filter->num_fields];
			for ( int j = 0; j < filter->num_fields; ++j )
				arg_fields[j] = new LogField(*filter->fields[j]);

			if ( filter->local )
				{
				writer = CreateWriter(stream->id, filter->writer, path, filter->num_fields, arg_fields);

				if ( ! writer )
					{
					Unref(columns);
					return false;
					}
				}

			if ( filter->remote )
				remote_serializer->SendLogCreateWriter(stream->id, filter->writer, path, filter->num_fields, arg_fields);
			}

		// Alright, can do the write now.

		LogVal** vals = RecordToFilterVals(filter, columns);

		if ( filter->remote )
			remote_serializer->SendLogWrite(stream->id, filter->writer, path, filter->num_fields, vals);

		if ( filter->local && ! writer->Write(filter->num_fields, vals) )
			error = true;

#ifdef DEBUG
		DBG_LOG(DBG_LOGGING, "Wrote record to filter '%s' on stream '%s'", filter->name.c_str(), stream->name.c_str());
#endif
		}

	Unref(columns);

	if ( error )
		RemoveDisabledWriters(stream);

	return true;
	}

LogVal* LogMgr::ValToLogVal(Val* val)
	{
	LogVal* lval = new LogVal(val->Type()->Tag());

	switch ( lval->type ) {
	case TYPE_BOOL:
	case TYPE_INT:
		lval->val.int_val = val->InternalInt();
	break;

	case TYPE_ENUM:
		{
		const char* s = val->Type()->AsEnumType()->Lookup(val->InternalInt());
		lval->val.string_val = new string(s);
		break;
		}

	case TYPE_COUNT:
	case TYPE_COUNTER:
		lval->val.uint_val = val->InternalUnsigned();
		break;

	case TYPE_PORT:
		lval->val.uint_val = val->AsPortVal()->Port();
		break;

	case TYPE_SUBNET:
		lval->val.subnet_val = *val->AsSubNet();
		break;

	case TYPE_NET:
	case TYPE_ADDR:
		{
		addr_type t = val->AsAddr();
		copy_addr(&t, &lval->val.addr_val);
		break;
		}

	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
		lval->val.double_val = val->InternalDouble();
		break;

	case TYPE_STRING:
		{
		const BroString* s = val->AsString();
		lval->val.string_val = new string((const char*) s->Bytes(), s->Len());
		break;
		}

	case TYPE_TABLE:
		{
		ListVal* set = val->AsTableVal()->ConvertToPureList();
		lval->val.set_val.size = set->Length();
		lval->val.set_val.vals = new LogVal* [lval->val.set_val.size];

		for ( int i = 0; i < lval->val.set_val.size; i++ )
			lval->val.set_val.vals[i] = ValToLogVal(set->Index(i));

		break;
		}

		default:
			internal_error("unsupported type for log_write");
		}

	return lval;
	}

LogVal** LogMgr::RecordToFilterVals(Filter* filter, RecordVal* columns)
	{
	LogVal** vals = new LogVal*[filter->num_fields];

	for ( int i = 0; i < filter->num_fields; ++i )
		{
		TypeTag type = TYPE_ERROR;
		Val* val = columns;

		// For each field, first find the right value, which can potentially
		// be nested inside other records.
		list<int>& indices = filter->indices[i];

		for ( list<int>::iterator j = indices.begin(); j != indices.end(); ++j )
			{
			type = val->Type()->AsRecordType()->FieldType(*j)->Tag();
			val = val->AsRecordVal()->Lookup(*j);

			if ( ! val )
				{
				// Value, or any of its parents, is not set.
				vals[i] = new LogVal(type, false);
				break;
				}
			}

		if ( val )
			vals[i] = ValToLogVal(val);
		}

	return vals;
	}

LogWriter* LogMgr::CreateWriter(EnumVal* id, EnumVal* writer, string path, int num_fields, LogField** fields)
	{
	Stream* stream = FindStream(id);

	if ( ! stream )
		// Don't know this stream.
		return false;

	Stream::WriterMap::iterator w = stream->writers.find(Stream::WriterPathPair(writer->AsEnum(), path));

	if ( w != stream->writers.end() )
		// If we already have a writer for this. That's fine, we just return
		// it.
		return w->second->writer;

	// Need to instantiate a new writer.

    LogWriterDefinition* ld = log_writers;

	while ( true )
		{
		if ( ld->type == BifEnum::Log::WRITER_DEFAULT )
			{
			run_time("unknow writer when creating writer");
			return 0;
			}

		if ( ld->type == writer->AsEnum() )
			break;

		if ( ! ld->factory )
			// Oops, we can't instantuate this guy.
			return 0;

		// If the writer has an init function, call it.
		if ( ld->init )
			{
			if ( (*ld->init)() )
				// Clear the init function so that we won't call it again later.
				ld->init = 0;
			else
				// Init failed, disable by deleting factory function.
				ld->factory = 0;

			DBG_LOG(DBG_LOGGING, "failed to init writer class %s", ld->name);
			return false;
			}

		++ld;
		}

	assert(ld->factory);
	LogWriter* writer_obj = (*ld->factory)();

	if ( ! writer_obj->Init(path, num_fields, fields) )
		{
		DBG_LOG(DBG_LOGGING, "failed to init instance of writer %s", ld->name);
		return 0;
		}

	WriterInfo* winfo = new WriterInfo;
	winfo->type = writer->Ref()->AsEnumVal();
	winfo->writer = writer_obj;
	winfo->open_time = network_time;
	winfo->rotation_timer = 0;
	InstallRotationTimer(winfo);

	stream->writers.insert(Stream::WriterMap::value_type(Stream::WriterPathPair(writer->AsEnum(), path), winfo));

	return writer_obj;
	}

bool LogMgr::Write(EnumVal* id, EnumVal* writer, string path, int num_fields, LogVal** vals)
	{
	Stream* stream = FindStream(id);

	if ( ! stream )
		{
		// Don't know this stream.
#ifdef DEBUG
		ODesc desc;
		id->Describe(&desc);
		DBG_LOG(DBG_LOGGING, "unknown stream %s in LogMgr::Write()", desc.Description());
#endif
		return false;
		}

	if ( ! stream->enabled )
		return true;

	Stream::WriterMap::iterator w = stream->writers.find(Stream::WriterPathPair(writer->AsEnum(), path));

	if ( w == stream->writers.end() )
		{
		// Don't know this writer.
#ifdef DEBUG
		ODesc desc;
		id->Describe(&desc);
		DBG_LOG(DBG_LOGGING, "unknown writer %s in LogMgr::Write()", desc.Description());
#endif
		return false;
		}

	bool success = w->second->writer->Write(num_fields, vals);

	DBG_LOG(DBG_LOGGING, "Wrote pre-filtered record to path '%s' on stream '%s' [%s]", path.c_str(), stream->name.c_str(), (success ? "ok" : "error"));

	return success;
	}

void LogMgr::SendAllWritersTo(RemoteSerializer::PeerID peer)
	{
	for ( vector<Stream *>::iterator s = streams.begin(); s != streams.end(); ++s )
		{
		Stream* stream = (*s);

		if ( ! stream )
			continue;

		for ( Stream::WriterMap::iterator i = stream->writers.begin(); i != stream->writers.end(); i++ )
			{
			LogWriter* writer = i->second->writer;
			EnumVal writer_val(i->first.first, BifType::Enum::Log::Writer);
			remote_serializer->SendLogCreateWriter(peer, (*s)->id, &writer_val, i->first.second, writer->NumFields(), writer->Fields());
			}
		}
	}

bool LogMgr::SetBuf(EnumVal* id, bool enabled)
	{
	Stream* stream = FindStream(id);
	if ( ! stream )
		return false;

	for ( Stream::WriterMap::iterator i = stream->writers.begin(); i != stream->writers.end(); i++ )
		i->second->writer->SetBuf(enabled);

	RemoveDisabledWriters(stream);

	return true;
	}

bool LogMgr::Flush(EnumVal* id)
	{
	Stream* stream = FindStream(id);
	if ( ! stream )
		return false;

	if ( ! stream->enabled )
		return true;

	for ( Stream::WriterMap::iterator i = stream->writers.begin(); i != stream->writers.end(); i++ )
		i->second->writer->Flush();

	RemoveDisabledWriters(stream);

	return true;
	}

void LogMgr::Error(LogWriter* writer, const char* msg)
	{
	run_time(fmt("error with writer for %s: %s", writer->Path().c_str(), msg));
	}

// Timer which on dispatching rotates the filter.
class RotationTimer : public Timer {
public:
	RotationTimer(double t, LogMgr::WriterInfo* arg_winfo, bool arg_rotate)
		: Timer(t, TIMER_ROTATE)	{ winfo = arg_winfo; rotate = arg_rotate; }
	~RotationTimer();

	void Dispatch(double t, int is_expire);

protected:
	LogMgr::WriterInfo* winfo;
	bool rotate;
};

RotationTimer::~RotationTimer()
	{
	if ( winfo->rotation_timer == this )
		winfo->rotation_timer = 0;
	}

void RotationTimer::Dispatch(double t, int is_expire)
	{
	winfo->rotation_timer = 0;

	if ( rotate )
		log_mgr->Rotate(winfo);

	if ( ! is_expire )
		{
		winfo->open_time = network_time;
		log_mgr->InstallRotationTimer(winfo);
		}
	}

RecordVal* LogMgr::LookupRotationControl(EnumVal* writer, string path)
	{
	TableVal* rc = BifConst::Log::rotation_control->AsTableVal();

	ListVal* index = new ListVal(TYPE_ANY);
	index->Append(writer->Ref());
	index->Append(new StringVal(path.c_str()));

	Val* r = rc->Lookup(index);
	assert(r);

	Unref(index);

	return r->AsRecordVal();
	}

void LogMgr::InstallRotationTimer(WriterInfo* winfo)
	{
	if ( terminating )
		return;

	if ( winfo->rotation_timer )
		{
		timer_mgr->Cancel(winfo->rotation_timer);
		winfo->rotation_timer = 0;
		}

	RecordVal* rc = LookupRotationControl(winfo->type, winfo->writer->Path());

	int idx = rc->Type()->AsRecordType()->FieldOffset("interv");
	double rotation_interval = rc->LookupWithDefault(idx)->AsInterval();

	if ( rotation_interval )
		{
		// When this is called for the first time, network_time can still be
		// zero. If so, we set a timer which fires immediately but doesn't
		// rotate when it expires.
		if ( ! network_time )
			winfo->rotation_timer = new RotationTimer(1, winfo, false);
		else
			{
			if ( ! winfo->open_time )
				winfo->open_time = network_time;

			const char* base_time = log_rotate_base_time ?
				log_rotate_base_time->AsString()->CheckString() : 0;

			double delta_t =
				calc_next_rotate(rotation_interval, base_time);

			winfo->rotation_timer = new RotationTimer(network_time + delta_t, winfo, true);
			}

		timer_mgr->Add(winfo->rotation_timer);

		DBG_LOG(DBG_LOGGING, "Scheduled rotation timer for %s to %.6f", winfo->writer->Path().c_str(), winfo->rotation_timer->Time());
		}
	}

void LogMgr::Rotate(WriterInfo* winfo)
	{
	DBG_LOG(DBG_LOGGING, "Rotating %s at %.6f", winfo->writer->Path().c_str(), network_time);

	// Create the RotationInfo record.
	RecordVal* info = new RecordVal(BifType::Record::Log::RotationInfo);
	info->Assign(0, winfo->type->Ref());
	info->Assign(1, new StringVal(winfo->writer->Path().c_str()));
	info->Assign(2, new Val(winfo->open_time, TYPE_TIME));
	info->Assign(3, new Val(network_time, TYPE_TIME));

	// Call the function building us the new path.

	Func* rotation_path_func = internal_func("Log::default_rotation_path_func");

	RecordVal* rc = LookupRotationControl(winfo->type, winfo->writer->Path());

	int idx = rc->Type()->AsRecordType()->FieldOffset("postprocessor");
	string rotation_postprocessor = rc->LookupWithDefault(idx)->AsString()->CheckString();

	val_list vl(1);
	vl.append(info);
	Val* result = rotation_path_func->Call(&vl);
	string new_path = result->AsString()->CheckString();
	Unref(result);

	winfo->writer->Rotate(new_path, rotation_postprocessor, winfo->open_time, network_time, terminating);
	}


