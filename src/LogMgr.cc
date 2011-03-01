
#include "LogMgr.h"
#include "Event.h"
#include "EventHandler.h"
#include "NetVar.h"

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

struct LogMgr::Stream {
 	EnumVal* id;
	string name;
	RecordType* columns;
	EventHandlerPtr event;
	list<Filter*> filters;

	typedef pair<int, string> WriterPathPair;
	typedef map<WriterPathPair, LogWriter *> WriterMap;
	WriterMap writers; // Writers indexed by id/path pair.

	~Stream();
	};


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
		delete i->second;

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
		run_time("unknown log stream");
		return 0;
		}

	return streams[idx];
	}

void LogMgr::RemoveDisabledWriters(Stream* stream)
	{
	list<Stream::WriterPathPair> disabled;

	for ( Stream::WriterMap::iterator j = stream->writers.begin(); j != stream->writers.end(); j++ )
		{
		if ( j->second->Disabled() )
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
	streams[idx]->name = id->Type()->AsEnumType()->Lookup(idx);
	streams[idx]->event = event ? event_registry->Lookup(event->GetID()->Name()) : 0;
	streams[idx]->columns = columns->Ref()->AsRecordType();

	DBG_LOG(DBG_LOGGING, "Created new logging stream '%s', raising event %s", streams[idx]->name.c_str(), event ? streams[idx]->event->Name() : "<none>");

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
				}
			else
				{
				run_time("unsupported field type for log column");
				return false;
				}

			continue;
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
	int writer = 0;
	int idx = rtype->FieldOffset("writer");
	writer = fval->LookupWithDefault(idx)->AsEnum();

	// Create a new Filter instance.

	Val* pred = fval->Lookup(rtype->FieldOffset("pred"));
	Val* path_func = fval->Lookup(rtype->FieldOffset("path_func"));

	Filter* filter = new Filter;
	filter->name = fval->Lookup(rtype->FieldOffset("name"))->AsString()->CheckString();
	filter->pred = pred ? pred->AsFunc() : 0;
	filter->path_func = path_func ? path_func->AsFunc() : 0;
	filter->writer = id->Ref()->AsEnumVal();
	filter->local = fval->LookupWithDefault(rtype->FieldOffset("log_local"))->AsBool();
	filter->remote = fval->LookupWithDefault(rtype->FieldOffset("log_remote"))->AsBool();

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

	stream->filters.push_back(filter);

#ifdef DEBUG
	DBG_LOG(DBG_LOGGING, "Created new filter '%s' for stream '%s'", filter->name.c_str(), stream->name.c_str());
	DBG_LOG(DBG_LOGGING, "   writer    : %d", filter->writer);
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

bool LogMgr::RemoveFilter(EnumVal* id, StringVal* filter)
	{
	Stream* stream = FindStream(id);
	if ( ! stream )
		return false;

	string name = filter->AsString()->CheckString();

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

	columns = columns->CoerceTo(stream->columns);

	if ( ! columns )
		{
		run_time("imcompatible log record type");
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

		if ( ! filter->local )
			// Skip the subsequent local logging code.
			continue;

		// See if we already have a writer for this path.
		Stream::WriterMap::iterator w = stream->writers.find(Stream::WriterPathPair(filter->writer->AsEnum(), path));

		LogWriter* writer = 0;

		if ( w != stream->writers.end() )
			// We have a writer already.
			writer = w->second;
		else
			{
			// No, need to create one.

			// Copy the fields for LogWriter::Init() as it will take
			// ownership.
			LogField** arg_fields = new LogField*[filter->num_fields];
			for ( int j = 0; j < filter->num_fields; ++j )
				arg_fields[j] = new LogField(*filter->fields[j]);

			writer = CreateWriter(stream->id, filter->writer, path, filter->num_fields, arg_fields);

			if ( ! writer )
				{
				Unref(columns);
				return false;
				}
			}

		// Alright, can do the write now.
		LogVal** vals = RecordToFilterVals(filter, columns);
		if ( ! writer->Write(filter->num_fields, vals) )
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

		if ( ! val )
			continue;

		switch ( val->Type()->Tag() ) {
		case TYPE_BOOL:
		case TYPE_INT:
		case TYPE_ENUM:
			vals[i] = new LogVal(type);
			vals[i]->val.int_val = val->InternalInt();
			break;

		case TYPE_COUNT:
		case TYPE_COUNTER:
		case TYPE_PORT:
			vals[i] = new LogVal(type);
			vals[i]->val.uint_val = val->InternalUnsigned();
			break;

		case TYPE_SUBNET:
			vals[i] = new LogVal(type);
			vals[i]->val.subnet_val = *val->AsSubNet();
			break;

		case TYPE_NET:
		case TYPE_ADDR:
			{
			vals[i] = new LogVal(type);
			addr_type t = val->AsAddr();
			copy_addr(&t, &vals[i]->val.addr_val);
			break;
			}

		case TYPE_DOUBLE:
		case TYPE_TIME:
		case TYPE_INTERVAL:
			vals[i] = new LogVal(type);
			vals[i]->val.double_val = val->InternalDouble();
			break;

		case TYPE_STRING:
			{
			const BroString* s = val->AsString();
			LogVal* lval = (LogVal*) new char[sizeof(LogVal) + sizeof(log_string_type) + s->Len()];
			new (lval) LogVal(type); // Run ctor.
			lval->val.string_val.len = s->Len();
			memcpy(&lval->val.string_val.string, s->Bytes(), s->Len());
			vals[i] = lval;
			break;
			}

		default:
			internal_error("unsupported type for log_write");
		}
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
		return w->second;

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

			return false;
			}

		++ld;
		}

	assert(ld->factory);
	LogWriter* writer_obj = (*ld->factory)();

	if ( ! writer_obj->Init(path, num_fields, fields) )
		return 0;

	stream->writers.insert(Stream::WriterMap::value_type(Stream::WriterPathPair(writer->AsEnum(), path), writer_obj));

	return writer_obj;
	}

bool LogMgr::Write(EnumVal* id, EnumVal* writer, string path, int num_fields, LogVal** vals)
	{
	Stream* stream = FindStream(id);

	if ( ! stream )
		// Don't know this stream.
		return false;

	Stream::WriterMap::iterator w = stream->writers.find(Stream::WriterPathPair(writer->AsEnum(), path));

	if ( w == stream->writers.end() )
		// Don't know this writer.
		return false;

	bool success = w->second->Write(num_fields, vals);

#ifdef DEBUG
	DBG_LOG(DBG_LOGGING, "Wrote pre-filtered record to '%s' on stream '%s'", path.c_str(), stream->name.c_str());
#endif

	return success;
	}

bool LogMgr::SetBuf(EnumVal* id, bool enabled)
	{
	Stream* stream = FindStream(id);
	if ( ! stream )
		return false;

	for ( Stream::WriterMap::iterator i = stream->writers.begin(); i != stream->writers.end(); i++ )
		i->second->SetBuf(enabled);

	RemoveDisabledWriters(stream);

	return true;
	}

bool LogMgr::Flush(EnumVal* id)
	{
	Stream* stream = FindStream(id);
	if ( ! stream )
		return false;

	for ( Stream::WriterMap::iterator i = stream->writers.begin(); i != stream->writers.end(); i++ )
		i->second->Flush();

	RemoveDisabledWriters(stream);

	return true;
	}

void LogMgr::Error(LogWriter* writer, const char* msg)
	{
	run_time(fmt("error with writer for %s: %s", writer->Path().c_str(), msg));
	}
