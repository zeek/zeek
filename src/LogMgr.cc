// See the file "COPYING" in the main distribution directory for copyright.

#include <algorithm>

#include "LogMgr.h"
#include "Event.h"
#include "EventHandler.h"
#include "NetVar.h"
#include "Net.h"

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

	// Vector indexed by field number. Each element is a list of record
	// indices defining a path leading to the value across potential
	// sub-records.
	vector<list<int> > indices;

	~Filter();
};

struct LogMgr::WriterInfo {
	EnumVal* type;
	double open_time;
	Timer* rotation_timer;
	LogEmissary *writer;
	
	WriterInfo()
	: type(NULL), open_time(0), rotation_timer(NULL), 
	writer(NULL) { }
	
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

	WriterMap writers;	// Writers indexed by id/path pair.
	
	Stream()
	: id(NULL), enabled(false), name(""), columns(NULL)
	{ }

	~Stream();
	};

LogMgr::Filter::~Filter()
	{
	for ( int i = 0; i < num_fields; ++i )
		delete fields[i];

	free(fields);

	Unref(path_val);
	}

LogMgr::Stream::~Stream()
	{
	Unref(columns);

	for ( WriterMap::iterator i = writers.begin(); i != writers.end(); i++ )
		{
		WriterInfo* winfo = i->second;

		if ( ! winfo )
			continue;

		if ( winfo->rotation_timer )
			timer_mgr->Cancel(winfo->rotation_timer);

		Unref(winfo->type);
		delete winfo->writer;
		delete winfo;
		}

	for ( list<Filter*>::iterator f = filters.begin(); f != filters.end(); ++f )
		delete *f;
	}


LogMgr::LogMgr()
: hasShutdown(false)
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
		return 0;

	return streams[idx];
	}

LogMgr::WriterInfo* LogMgr::FindWriter(LogEmissary* writer)
	{
	for ( vector<Stream *>::iterator s = streams.begin(); s != streams.end(); ++s )
		{
		if ( ! *s )
			continue;

		for ( Stream::WriterMap::iterator i = (*s)->writers.begin(); i != (*s)->writers.end(); i++ )
			{
			WriterInfo* winfo = i->second;

			if ( winfo->writer == writer )
				return winfo;
			}
		}

	return 0;
	}

void LogMgr::UpdateWriters(Stream* stream)
	{
	for ( Stream::WriterMap::iterator j = stream->writers.begin(); j != stream->writers.end(); ++j )
		{
		if ( j->second )
			{
			j->second->writer->Update();
			}
		}
	/*
	list<Stream::WriterPathPair> disabled;

	for ( Stream::WriterMap::iterator j = stream->writers.begin(); j != stream->writers.end(); j++ )
		{
		if ( j->second && j->second->writer->Disabled() )
			{
			delete j->second;
			disabled.push_back(j->first);
			}
		}

	for ( list<Stream::WriterPathPair>::iterator j = disabled.begin(); j != disabled.end(); j++ )
		stream->writers.erase(*j);
	*/
	}

bool LogMgr::CreateStream(EnumVal* id, RecordVal* sval)
	{
	RecordType* rtype = sval->Type()->AsRecordType();

	if ( ! same_type(rtype, BifType::Record::Log::Stream, 0) )
		{
		reporter->Error("sval argument not of right type");
		return false;
		}

	RecordType* columns = sval->Lookup(rtype->FieldOffset("columns"))
		->AsType()->AsTypeType()->Type()->AsRecordType();

	bool log_attr_present = false;

	for ( int i = 0; i < columns->NumFields(); i++ )
		{
		if ( ! (columns->FieldDecl(i)->FindAttr(ATTR_LOG)) )
		    continue;

		if ( ! LogVal::IsCompatibleType(columns->FieldType(i)) )
			{
			reporter->Error("type of field '%s' is not support for logging output",
				 columns->FieldName(i));

			return false;
			}

		log_attr_present = true;
		}

	if ( ! log_attr_present )
		{
		reporter->Error("logged record type does not have any &log attributes");
		return false;
		}

	Val* event_val = sval->Lookup(rtype->FieldOffset("ev"));
	Func* event = event_val ? event_val->AsFunc() : 0;

	if ( event )
		{
		// Make sure the event is prototyped as expected.
		FuncType* etype = event->FType()->AsFuncType();

		if ( ! etype->IsEvent() )
			{
			reporter->Error("stream event is a function, not an event");
			return false;
			}

		const type_list* args = etype->ArgTypes()->Types();

		if ( args->length() != 1 )
			{
			reporter->Error("stream event must take a single argument");
			return false;
			}

		if ( ! same_type((*args)[0], columns) )
			{
			reporter->Error("stream event's argument type does not match column record type");
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

	DBG_LOG(DBG_LOGGING, "Created new logging stream '%s', raising event %s",
		streams[idx]->name.c_str(), event ? streams[idx]->event->Name() : "<none>");

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
bool LogMgr::TraverseRecord(Stream* stream, Filter* filter, RecordType* rt,
			    TableVal* include, TableVal* exclude, string path, list<int> indices)
	{
	for ( int i = 0; i < rt->NumFields(); ++i )
		{
		BroType* t = rt->FieldType(i);

		// Ignore if &log not specified.
		if ( ! rt->FieldDecl(i)->FindAttr(ATTR_LOG) )
			continue;

		list<int> new_indices = indices;
		new_indices.push_back(i);

		// Build path name.
		string new_path;

		if ( ! path.size() )
			new_path = rt->FieldName(i);
		else
			new_path = path + "." + rt->FieldName(i);

		if ( t->InternalType() == TYPE_INTERNAL_OTHER )
			{
			if ( t->Tag() == TYPE_RECORD )
				{
				// Recurse.
				if ( ! TraverseRecord(stream, filter,
						      t->AsRecordType(),
						      include,
						      exclude,
						      new_path,
						      new_indices) )
					return false;

				continue;
				}

			else if ( t->Tag() == TYPE_TABLE &&
				  t->AsTableType()->IsSet() )
				{
				// That's ok, we handle it below.
				}

			else if ( t->Tag() == TYPE_VECTOR )
				{
				// That's ok, we handle it below.
				}

			else if ( t->Tag() == TYPE_FILE )
				{
				// That's ok, we handle it below.
				}

			else if ( t->Tag() == TYPE_FUNC )
				{
				// That's ok, we handle it below.
				}

			else
				{
				reporter->Error("unsupported field type for log column");
				return false;
				}
			}

		// If include fields are specified, only include if explicitly listed.
		if ( include )
			{
			StringVal* new_path_val = new StringVal(new_path.c_str());
			bool result = include->Lookup(new_path_val);

			Unref(new_path_val);

			if ( ! result )
				continue;
			}

		// If exclude fields are specified, do not only include if listed.
		if ( exclude )
			{
			StringVal* new_path_val = new StringVal(new_path.c_str());
			bool result = exclude->Lookup(new_path_val);

			Unref(new_path_val);

			if ( result )
				continue;
			}

		// Alright, we want this field.

		filter->indices.push_back(new_indices);

		filter->fields = (LogField**)
			realloc(filter->fields,
				sizeof(LogField) * ++filter->num_fields);

		if ( ! filter->fields )
			{
			reporter->Error("out of memory in add_filter");
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
		reporter->Error("filter argument not of right type");
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

	// Build the list of fields that the filter wants included, including
	// potentially rolling out fields.
	Val* include = fval->Lookup(rtype->FieldOffset("include"));
	Val* exclude = fval->Lookup(rtype->FieldOffset("exclude"));

	filter->num_fields = 0;
	filter->fields = 0;
	if ( ! TraverseRecord(stream, filter, stream->columns,
			      include ? include->AsTableVal() : 0,
			      exclude ? exclude->AsTableVal() : 0,
			      "", list<int>()) )
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
		// If no path is given, use the Stream ID as the default but
		// strip the namespace.
		const char* s = stream->name.c_str();
		const char* e = s + strlen(s);

		const char* t = strstr(s, "::");
		if ( t )
			s = t + 2;

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

	DBG_LOG(DBG_LOGGING, "Created new filter '%s' for stream '%s'",
		filter->name.c_str(), stream->name.c_str());

	DBG_LOG(DBG_LOGGING, "   writer    : %s", desc.Description());
	DBG_LOG(DBG_LOGGING, "   path      : %s", filter->path.c_str());
	DBG_LOG(DBG_LOGGING, "   path_func : %s", (filter->path_func ? "set" : "not set"));
	DBG_LOG(DBG_LOGGING, "   pred      : %s", (filter->pred ? "set" : "not set"));

	for ( int i = 0; i < filter->num_fields; i++ )
		{
		LogField* field = filter->fields[i];
		DBG_LOG(DBG_LOGGING, "   field %10s: %s",
			field->name.c_str(), type_name(field->type));
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

	for ( list<Filter*>::iterator i = stream->filters.begin();
	      i != stream->filters.end(); ++i )
		{
		if ( (*i)->name == name )
			{
			Filter* filter = *i;
			stream->filters.erase(i);
			DBG_LOG(DBG_LOGGING, "Removed filter '%s' from stream '%s'",
				filter->name.c_str(), stream->name.c_str());
			delete filter;
			return true;
			}
		}

	// If we don't find the filter, we don't treat that as an error.
	DBG_LOG(DBG_LOGGING, "No filter '%s' for removing from stream '%s'",
		name.c_str(), stream->name.c_str());

	return true;
	}

bool LogMgr::Write(EnumVal* id, RecordVal* columns)
	{
	bool error = false;

	Stream* stream = FindStream(id);
	if ( ! stream )
		{
		reporter->Error("Tried to write to unknown stream.");
		return false;
		}
	if ( ! stream->enabled )
		{
		reporter->Error("Tried to write to disabled stream.");
		// assert(false);
		return true;
		}
	columns = columns->CoerceTo(stream->columns);

	if ( ! columns )
		{
		reporter->Error("incompatible log record type");
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
	for ( list<Filter*>::iterator i = stream->filters.begin();
	      i != stream->filters.end(); ++i )
		{
		Filter* filter = *i;
		string path = filter->path;

		if ( filter->pred )
			{
			// See whether the predicates indicates that we want
			// to log this record.
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
			val_list vl(3);
			vl.append(id->Ref());
			vl.append(filter->path_val->Ref());
			vl.append(columns->Ref());
			Val* v = filter->path_func->Call(&vl);

			if ( ! v->Type()->Tag() == TYPE_STRING )
				{
				reporter->Error("path_func did not return string");
				Unref(v);
				return false;
				}

			path = v->AsString()->CheckString();
			Unref(v);

#ifdef DEBUG
			DBG_LOG(DBG_LOGGING, "Path function for filter '%s' on stream '%s' return '%s'",
				filter->name.c_str(), stream->name.c_str(), path.c_str());
#endif
			}

		// See if we already have a writer for this path.
		Stream::WriterMap::iterator w =
			stream->writers.find(Stream::WriterPathPair(filter->writer->AsEnum(), path));

		LogEmissary* writer = NULL;

		if ( w != stream->writers.end() )
			// We know this writer already.
			writer = w->second ? w->second->writer : 0;

		else
			{
			// No, need to create one.

			// Copy the fields for LogEmissary::Init() as it will take
			// ownership.
			LogField** arg_fields = new LogField*[filter->num_fields];

			for ( int j = 0; j < filter->num_fields; ++j )
				arg_fields[j] = new LogField(*filter->fields[j]);

			if ( filter->local )
				{
				writer = CreateWriter(stream->id, filter->writer,
						      path, filter->num_fields,
						      arg_fields);

				if ( ! writer )
					{
					Unref(columns);
					return false;
					}
				}
			else
				// Insert a null pointer into the map to make
				// sure we don't try creating it again.
				stream->writers.insert(Stream::WriterMap::value_type(
				Stream::WriterPathPair(filter->writer->AsEnum(), path), 0));

			if ( filter->remote )
				remote_serializer->SendLogCreateWriter(stream->id,
								       filter->writer,
								       path,
								       filter->num_fields,
								       arg_fields);
			}

		// Alright, can do the write now.

		if ( filter->local || filter->remote )
			{
			LogVal** vals = RecordToFilterVals(stream, filter, columns);

			if ( filter->remote )
				remote_serializer->SendLogWrite(stream->id,
								filter->writer,
								path,
								filter->num_fields,
								vals);

			if ( filter->local )
				{
				assert(writer);

				// Write takes ownership of vals.
				if ( ! writer->Write(filter->num_fields, vals) )
					error = true;
				}

			else
				DeleteVals(filter->num_fields, vals);

			}


#ifdef DEBUG
		DBG_LOG(DBG_LOGGING, "Wrote record to filter '%s' on stream '%s'",
			filter->name.c_str(), stream->name.c_str());
#endif
		}

	Unref(columns);

	if ( error )
		UpdateWriters(stream);

	return true;
	}

LogVal* LogMgr::ValToLogVal(Val* val, BroType* ty)
	{
	if ( ! ty )
		ty = val->Type();

	if ( ! val )
		return new LogVal(ty->Tag(), false);

	LogVal* lval = new LogVal(ty->Tag());

	switch ( lval->type ) {
	case TYPE_BOOL:
	case TYPE_INT:
		lval->val.int_val = val->InternalInt();
		break;

	case TYPE_ENUM:
		{
		const char* s =
			val->Type()->AsEnumType()->Lookup(val->InternalInt());

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
#ifdef BROv6
		copy_addr(t, lval->val.addr_val);
#else
		copy_addr(&t, lval->val.addr_val);
#endif
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
		lval->val.string_val =
			new string((const char*) s->Bytes(), s->Len());
		break;
		}

	case TYPE_FILE:
		{
		const BroFile* f = val->AsFile();
		lval->val.string_val = new string(f->Name());
		break;
		}

	case TYPE_FUNC:
		{
		ODesc d;
		const Func* f = val->AsFunc();
		f->Describe(&d);
		lval->val.string_val = new string(d.Description());
		break;
		}

	case TYPE_TABLE:
		{
		ListVal* set = val->AsTableVal()->ConvertToPureList();
		if ( ! set )
			// ConvertToPureList has reported an internal warning
			// already. Just keep going by making something up.
			set = new ListVal(TYPE_INT);

		lval->val.set_val.size = set->Length();
		lval->val.set_val.vals = new LogVal* [lval->val.set_val.size];

		for ( int i = 0; i < lval->val.set_val.size; i++ )
			lval->val.set_val.vals[i] = ValToLogVal(set->Index(i));

		Unref(set);
		break;
		}

	case TYPE_VECTOR:
		{
		VectorVal* vec = val->AsVectorVal();
		lval->val.vector_val.size = vec->Size();
		lval->val.vector_val.vals =
			new LogVal* [lval->val.vector_val.size];

		for ( int i = 0; i < lval->val.vector_val.size; i++ )
			{
			lval->val.vector_val.vals[i] =
				ValToLogVal(vec->Lookup(i),
					    vec->Type()->YieldType());
			}

		break;
		}

	default:
		reporter->InternalError("unsupported type for log_write");
	}

	return lval;
	}

LogVal** LogMgr::RecordToFilterVals(Stream* stream, Filter* filter,
				    RecordVal* columns)
	{
	LogVal** vals = new LogVal*[filter->num_fields];

	for ( int i = 0; i < filter->num_fields; ++i )
		{
		TypeTag type = TYPE_ERROR;
		Val* val = columns;

		// For each field, first find the right value, which can
		// potentially be nested inside other records.
		list<int>& indices = filter->indices[i];

		for ( list<int>::iterator j = indices.begin(); j != indices.end(); ++j )
			{
			type = val->Type()->AsRecordType()->FieldType(*j)->Tag();
			val = val->AsRecordVal()->Lookup(*j);

			if ( ! val )
				{
				// Value, or any of its parents, is not set.
				vals[i] = new LogVal(filter->fields[i]->type, false);
				break;
				}
			}

		if ( val )
			vals[i] = ValToLogVal(val);
		}

	return vals;
	}

LogEmissary* LogMgr::CreateWriter(EnumVal* id, EnumVal* writer, string path,
				int num_fields, LogField** fields)
	{
	Stream* stream = FindStream(id);

	if ( ! stream )
		// Don't know this stream.
		return false;

	Stream::WriterMap::iterator w =
		stream->writers.find(Stream::WriterPathPair(writer->AsEnum(), path));

	if ( w != stream->writers.end() && w->second )
		// If we already have a writer for this. That's fine, we just
		// return it.
		return w->second->writer;

	LogEmissary *emissary = LogWriterRegistrar::LaunchWriterThread(path, num_fields, fields, writer->AsEnum());
	DBG_LOG(DBG_LOGGING, "Launched new writer thread (0x%p -- %.3f)", emissary, open_time);

	WriterInfo* winfo = new WriterInfo;
	winfo->type = writer->Ref()->AsEnumVal();
	winfo->writer = emissary;
	winfo->open_time = network_time;
	winfo->rotation_timer = 0;
	InstallRotationTimer(winfo);

	stream->writers.insert(
		Stream::WriterMap::value_type(Stream::WriterPathPair(writer->AsEnum(), path),
		winfo));

	return emissary;
	}

void LogMgr::DeleteVals(int num_fields, LogVal** vals)
	{
	for ( int i = 0; i < num_fields; i++ )
		delete vals[i];

	delete [] vals;
	}

bool LogMgr::Write(EnumVal* id, EnumVal* writer, string path, int num_fields,
		   LogVal** vals)
	{
	Stream* stream = FindStream(id);

	if ( ! stream )
		{
		// Don't know this stream.
#ifdef DEBUG
		ODesc desc;
		id->Describe(&desc);
		DBG_LOG(DBG_LOGGING, "unknown stream %s in LogMgr::Write()",
			desc.Description());
#endif
		DeleteVals(num_fields, vals);
		return false;
		}

	if ( ! stream->enabled )
		{
		DeleteVals(num_fields, vals);
		return true;
		}

	Stream::WriterMap::iterator w =
		stream->writers.find(Stream::WriterPathPair(writer->AsEnum(), path));

	if ( w == stream->writers.end() )
		{
		// Don't know this writer.
#ifdef DEBUG
		ODesc desc;
		id->Describe(&desc);
		DBG_LOG(DBG_LOGGING, "unknown writer %s in LogMgr::Write()",
			desc.Description());
#endif
		DeleteVals(num_fields, vals);
		return false;
		}

	bool success = (w->second ? w->second->writer->Write(num_fields, vals) : true);

	DBG_LOG(DBG_LOGGING,
		"Wrote pre-filtered record to path '%s' on stream '%s' [%s]",
		path.c_str(), stream->name.c_str(), (success ? "ok" : "error"));

	return success;
	}

void LogMgr::Shutdown()
	{
	if(hasShutdown)
		return;
	
	for ( vector<Stream *>::iterator s = streams.begin(); s != streams.end(); ++s )
		{
		Stream* stream = (*s);

		if ( ! stream )
			continue;

		for ( Stream::WriterMap::iterator i = stream->writers.begin();
		      i != stream->writers.end(); i++ )
			{
			if(!i->second)
				{
				DBG_LOG(DBG_LOGGING, "BUG: WriterInfo with NULL LogEmissary.");
				continue;
				}
			LogEmissary* writer = i->second->writer;
			DBG_LOG(DBG_LOGGING, "(0x%p) Commencing thread shutdown...", i->second->writer);
			writer->Shutdown();
			DBG_LOG(DBG_LOGGING, "(0x%p) Thread shutdown complete.", i->second->writer);
			}

		stream->enabled = false;
		}
	
	hasShutdown = true;
	}

void LogMgr::SendAllWritersTo(RemoteSerializer::PeerID peer)
	{
	for ( vector<Stream *>::iterator s = streams.begin(); s != streams.end(); ++s )
		{
		Stream* stream = (*s);

		if ( ! stream )
			continue;

		for ( Stream::WriterMap::iterator i = stream->writers.begin();
		      i != stream->writers.end(); i++ )
			{
			if ( ! i->second )
				continue;
			
			LogEmissary* writer = i->second->writer;
			EnumVal writer_val(i->first.first, BifType::Enum::Log::Writer);
			remote_serializer->SendLogCreateWriter(peer, (*s)->id,
							       &writer_val,
							       i->first.second,
							       writer->NumFields(),
							       writer->Fields());
			}
		}
	}

bool LogMgr::SetBuf(EnumVal* id, bool enabled)
	{
	Stream* stream = FindStream(id);
	if ( ! stream )
		return false;

	for ( Stream::WriterMap::iterator i = stream->writers.begin();
	      i != stream->writers.end(); i++ )
		{
		if ( i->second )
			i->second->writer->SetBuf(enabled);
		}

	UpdateWriters(stream);

	return true;
	}

bool LogMgr::Flush(EnumVal* id)
	{
	Stream* stream = FindStream(id);
	if ( ! stream )
		return false;

	if ( ! stream->enabled )
		return true;

	for ( Stream::WriterMap::iterator i = stream->writers.begin();
	      i != stream->writers.end(); i++ )
		{
		if ( i->second )
			i->second->writer->Flush();
		}

	UpdateWriters(stream);

	return true;
	}

void LogMgr::Error(LogEmissary* writer, const char* msg)
	{
	reporter->Error(fmt("error with writer for %s: %s",
		     writer->Path().c_str(), msg));
	}

// Timer which on dispatching rotates the filter.
class RotationTimer : public Timer {
public:
	RotationTimer(double t, LogMgr::WriterInfo* arg_winfo, bool arg_rotate)
		: Timer(t, TIMER_ROTATE)
			{
			winfo = arg_winfo;
			rotate = arg_rotate;
			}

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
		{
		log_mgr->Rotate(winfo);
		}

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

	RecordVal* rc =
		LookupRotationControl(winfo->type, winfo->writer->Path());

	assert(rc);

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

			winfo->rotation_timer =
				new RotationTimer(network_time + delta_t, winfo, true);
			}

		timer_mgr->Add(winfo->rotation_timer);

		DBG_LOG(DBG_LOGGING, "Scheduled rotation timer for %s to %.6f",
			winfo->writer->Path().c_str(), winfo->rotation_timer->Time());
		}
	}

void LogMgr::Rotate(WriterInfo* winfo)
	{
	DBG_LOG(DBG_LOGGING, "Rotating %s at %.6f",
		winfo->writer->Path().c_str(), network_time);

	// Build a temporary path for the writer to move the file to.
	struct tm tm;
	char buf[128];
	const char* const date_fmt = "%y-%m-%d_%H.%M.%S";
	time_t teatime = (time_t)winfo->open_time;

	localtime_r(&teatime, &tm);
	strftime(buf, sizeof(buf), date_fmt, &tm);

	string tmp = string(fmt("%s-%s", winfo->writer->Path().c_str(), buf));

	// Process any pending events, then trigger the rotation.
	winfo->writer->Update();
	winfo->writer->Rotate(tmp, winfo->open_time, network_time, terminating);
	}

bool LogMgr::FinishedRotation(LogEmissary* writer, string new_name, string old_name,
		      double open, double close, bool terminating)
	{
	DBG_LOG(DBG_LOGGING, "Finished rotating %s at %.6f, new name %s",
		writer->Path().c_str(), network_time, new_name.c_str());

	WriterInfo* winfo = FindWriter(writer);
	assert(winfo);

	RecordVal* rc =
		LookupRotationControl(winfo->type, winfo->writer->Path());

	assert(rc);

	// Create the RotationInfo record.
	RecordVal* info = new RecordVal(BifType::Record::Log::RotationInfo);
	info->Assign(0, winfo->type->Ref());
	info->Assign(1, new StringVal(new_name.c_str()));
	info->Assign(2, new StringVal(winfo->writer->Path().c_str()));
	info->Assign(3, new Val(open, TYPE_TIME));
	info->Assign(4, new Val(close, TYPE_TIME));
	info->Assign(5, new Val(terminating, TYPE_BOOL));

	int idx = rc->Type()->AsRecordType()->FieldOffset("postprocessor");
	assert(idx >= 0);

	Val* func = rc->Lookup(idx);
	if ( ! func )
		{
		ID* id = global_scope()->Lookup("Log::__default_rotation_postprocessor");
		assert(id);
		func = id->ID_Val();
		}

	assert(func);

	// Call the postprocessor function.
	val_list vl(1);
	vl.append(info);
	Val* v = func->AsFunc()->Call(&vl);
	int result = v->AsBool();
	Unref(v);
	return result;
	}

