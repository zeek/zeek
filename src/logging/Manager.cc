// See the file "COPYING" in the main distribution directory for copyright.

#include <algorithm>

#include "../Event.h"
#include "../EventHandler.h"
#include "../NetVar.h"
#include "../Net.h"
#include "../Type.h"

#include "threading/Manager.h"
#include "threading/SerialTypes.h"

#include "Manager.h"
#include "WriterFrontend.h"
#include "WriterBackend.h"
#include "logging.bif.h"

#ifdef ENABLE_BROKER
#include "broker/Manager.h"
#endif

using namespace logging;

struct Manager::Filter {
	string name;
	EnumVal* id;
	Func* pred;
	Func* path_func;
	string path;
	Val* path_val;
	EnumVal* writer;
	TableVal* config;
	bool local;
	bool remote;
	double interval;
	Func* postprocessor;

	int num_fields;
	threading::Field** fields;

	// Vector indexed by field number. Each element is a list of record
	// indices defining a path leading to the value across potential
	// sub-records.
	vector<list<int> > indices;

	~Filter();
};

struct Manager::WriterInfo {
	EnumVal* type;
	double open_time;
	Timer* rotation_timer;
	double interval;
	Func* postprocessor;
	WriterFrontend* writer;
	WriterBackend::WriterInfo* info;
	bool from_remote;
	string instantiating_filter;
	};

struct Manager::Stream {
 	EnumVal* id;
	bool enabled;
	string name;
	RecordType* columns;
	EventHandlerPtr event;
	list<Filter*> filters;

	typedef pair<int, string> WriterPathPair;

	typedef map<WriterPathPair, WriterInfo*> WriterMap;

	WriterMap writers;	// Writers indexed by id/path pair.

#ifdef ENABLE_BROKER
	bool enable_remote;
	int remote_flags;
#endif

	~Stream();
	};

Manager::Filter::~Filter()
	{
	for ( int i = 0; i < num_fields; ++i )
		delete fields[i];

	free(fields);

	Unref(path_val);
	}

Manager::Stream::~Stream()
	{
	Unref(columns);

	for ( WriterMap::iterator i = writers.begin(); i != writers.end(); i++ )
		{
		WriterInfo* winfo = i->second;

		if ( winfo->rotation_timer )
			timer_mgr->Cancel(winfo->rotation_timer);

		Unref(winfo->type);
		delete winfo->writer;
		delete winfo->info;
		delete winfo;
		}

	for ( list<Filter*>::iterator f = filters.begin(); f != filters.end(); ++f )
		delete *f;
	}

Manager::Manager()
	: plugin::ComponentManager<logging::Tag, logging::Component>("Log", "Writer")
	{
	rotations_pending = 0;
	}

Manager::~Manager()
	{
	for ( vector<Stream *>::iterator s = streams.begin(); s != streams.end(); ++s )
		delete *s;
	}

WriterBackend* Manager::CreateBackend(WriterFrontend* frontend, EnumVal* tag)
	{
	Component* c = Lookup(tag);

	if ( ! c )
		{
		reporter->Error("unknown writer type requested");
		return 0;
		}

	WriterBackend* backend = (*c->Factory())(frontend);
	assert(backend);

	return backend;
	}

Manager::Stream* Manager::FindStream(EnumVal* id)
	{
	unsigned int idx = id->AsEnum();

	if ( idx >= streams.size() || ! streams[idx] )
		return 0;

	return streams[idx];
	}

Manager::WriterInfo* Manager::FindWriter(WriterFrontend* writer)
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

bool Manager::CompareFields(const Filter* filter, const WriterFrontend* writer)
	{
	if ( filter->num_fields != writer->NumFields() )
		return false;

	for ( int i = 0; i < filter->num_fields; ++ i)
		if ( filter->fields[i]->type != writer->Fields()[i]->type )
			return false;

	return true;
	}

bool Manager::CheckFilterWriterConflict(const WriterInfo* winfo, const Filter* filter)
	{
	if ( winfo->from_remote )
		// If the writer was instantiated as a result of remote logging, then
		// a filter and writer are only compatible if field types match
		return ! CompareFields(filter, winfo->writer);
	else
		// If the writer was instantiated locally, it is bound to one filter
		return winfo->instantiating_filter != filter->name;
	}

void Manager::RemoveDisabledWriters(Stream* stream)
	{
	list<Stream::WriterPathPair> disabled;

	for ( Stream::WriterMap::iterator j = stream->writers.begin(); j != stream->writers.end(); j++ )
		{
		if ( j->second->writer->Disabled() )
			{
			j->second->writer->Stop();
			delete j->second;
			disabled.push_back(j->first);
			}
		}

	for ( list<Stream::WriterPathPair>::iterator j = disabled.begin(); j != disabled.end(); j++ )
		stream->writers.erase(*j);
	}

bool Manager::CreateStream(EnumVal* id, RecordVal* sval)
	{
	RecordType* rtype = sval->Type()->AsRecordType();

	if ( ! same_type(rtype, BifType::Record::Log::Stream, 0) )
		{
		reporter->Error("sval argument not of right type");
		return false;
		}

	RecordType* columns = sval->Lookup("columns")
		->AsType()->AsTypeType()->Type()->AsRecordType();

	bool log_attr_present = false;

	for ( int i = 0; i < columns->NumFields(); i++ )
		{
		if ( ! (columns->FieldDecl(i)->FindAttr(ATTR_LOG)) )
		    continue;

		if ( ! threading::Value::IsCompatibleType(columns->FieldType(i)) )
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

	Val* event_val = sval->Lookup("ev");
	Func* event = event_val ? event_val->AsFunc() : 0;

	if ( event )
		{
		// Make sure the event is prototyped as expected.
		FuncType* etype = event->FType()->AsFuncType();

		if ( etype->Flavor() != FUNC_FLAVOR_EVENT )
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
	streams[idx]->event = event ? event_registry->Lookup(event->Name()) : 0;
	streams[idx]->columns = columns->Ref()->AsRecordType();

#ifdef ENABLE_BROKER
	streams[idx]->enable_remote = internal_val("Log::enable_remote_logging")->AsBool();
	streams[idx]->remote_flags = broker::PEERS;
#endif

	DBG_LOG(DBG_LOGGING, "Created new logging stream '%s', raising event %s",
		streams[idx]->name.c_str(), event ? streams[idx]->event->Name() : "<none>");

	return true;
	}

bool Manager::RemoveStream(EnumVal* id)
	{
	unsigned int idx = id->AsEnum();

	if ( idx >= streams.size() || ! streams[idx] )
		return false;

	Stream* stream = streams[idx];

	if ( ! stream )
		return false;

	for ( Stream::WriterMap::iterator i = stream->writers.begin(); i != stream->writers.end(); i++ )
		{
		WriterInfo* winfo = i->second;

		DBG_LOG(DBG_LOGGING, "Removed writer '%s' from stream '%s'",
			winfo->writer->Name(), stream->name.c_str());

		winfo->writer->Stop();
		delete winfo->writer;
		delete winfo;
		}

	stream->writers.clear();
	string sname(stream->name);
	delete stream;
	streams[idx] = 0;

	DBG_LOG(DBG_LOGGING, "Removed logging stream '%s'", sname.c_str());
	return true;
	}

bool Manager::EnableStream(EnumVal* id)
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

bool Manager::DisableStream(EnumVal* id)
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
bool Manager::TraverseRecord(Stream* stream, Filter* filter, RecordType* rt,
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

		void* tmp =
			realloc(filter->fields,
				sizeof(threading::Field*) * (filter->num_fields + 1));

		if ( ! tmp )
			{
			reporter->Error("out of memory in add_filter");
			return false;
			}

		++filter->num_fields;
		filter->fields = (threading::Field**) tmp;

		TypeTag st = TYPE_VOID;

		if ( t->Tag() == TYPE_TABLE )
			st = t->AsSetType()->Indices()->PureType()->Tag();

		else if ( t->Tag() == TYPE_VECTOR )
			st = t->AsVectorType()->YieldType()->Tag();

		bool optional = rt->FieldDecl(i)->FindAttr(ATTR_OPTIONAL);

		filter->fields[filter->num_fields - 1] = new threading::Field(new_path.c_str(), 0, t->Tag(), st, optional);
		}

	return true;
	}

bool Manager::AddFilter(EnumVal* id, RecordVal* fval)
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
	EnumVal* writer = fval->Lookup("writer", true)->AsEnumVal();

	// Create a new Filter instance.

	Val* name = fval->Lookup("name", true);
	Val* pred = fval->Lookup("pred", true);
	Val* path_func = fval->Lookup("path_func", true);
	Val* log_local = fval->Lookup("log_local", true);
	Val* log_remote = fval->Lookup("log_remote", true);
	Val* interv = fval->Lookup("interv", true);
	Val* postprocessor = fval->Lookup("postprocessor", true);
	Val* config = fval->Lookup("config", true);

	Filter* filter = new Filter;
	filter->name = name->AsString()->CheckString();
	filter->id = id->Ref()->AsEnumVal();
	filter->pred = pred ? pred->AsFunc() : 0;
	filter->path_func = path_func ? path_func->AsFunc() : 0;
	filter->writer = writer->Ref()->AsEnumVal();
	filter->local = log_local->AsBool();
	filter->remote = log_remote->AsBool();
	filter->interval = interv->AsInterval();
	filter->postprocessor = postprocessor ? postprocessor->AsFunc() : 0;
	filter->config = config->Ref()->AsTableVal();

	Unref(name);
	Unref(pred);
	Unref(path_func);
	Unref(log_local);
	Unref(log_remote);
	Unref(interv);
	Unref(postprocessor);
	Unref(config);

	// Build the list of fields that the filter wants included, including
	// potentially rolling out fields.
	Val* include = fval->Lookup("include");
	Val* exclude = fval->Lookup("exclude");

	filter->num_fields = 0;
	filter->fields = 0;
	if ( ! TraverseRecord(stream, filter, stream->columns,
			      include ? include->AsTableVal() : 0,
			      exclude ? exclude->AsTableVal() : 0,
			      "", list<int>()) )
		{
		delete filter;
		return false;
		}

	// Get the path for the filter.
	Val* path_val = fval->Lookup("path");

	if ( path_val )
		{
		filter->path = path_val->AsString()->CheckString();
		filter->path_val = path_val->Ref();
		}

	else
		{
		// If no path is given, it's derived based upon the value returned by
		// the first call to the filter's path_func (during first write).
		filter->path_val = 0;
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
		threading::Field* field = filter->fields[i];
		DBG_LOG(DBG_LOGGING, "   field %10s: %s",
			field->name, type_name(field->type));
		}
#endif

	return true;
	}

bool Manager::RemoveFilter(EnumVal* id, StringVal* name)
	{
	return RemoveFilter(id, name->AsString()->CheckString());
	}

bool Manager::RemoveFilter(EnumVal* id, string name)
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

bool Manager::Write(EnumVal* id, RecordVal* columns)
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

			int result = 1;

			Val* v = filter->pred->Call(&vl);
			if ( v )
				{
				result = v->AsBool();
				Unref(v);
				}

			if ( ! result )
				continue;
			}

		if ( filter->path_func )
			{
			val_list vl(3);
			vl.append(id->Ref());

			Val* path_arg;
			if ( filter->path_val )
				path_arg = filter->path_val->Ref();
			else
				path_arg = new StringVal("");

			vl.append(path_arg);

			Val* rec_arg;
			BroType* rt = filter->path_func->FType()->Args()->FieldType("rec");

			if ( rt->Tag() == TYPE_RECORD )
				rec_arg = columns->CoerceTo(rt->AsRecordType(), true);
			else
				// Can be TYPE_ANY here.
				rec_arg = columns->Ref();

			vl.append(rec_arg);

			Val* v = 0;

			v = filter->path_func->Call(&vl);

			if ( ! v )
				return false;

			if ( v->Type()->Tag() != TYPE_STRING )
				{
				reporter->Error("path_func did not return string");
				Unref(v);
				return false;
				}

			if ( ! filter->path_val )
				{
				filter->path = v->AsString()->CheckString();
				filter->path_val = v->Ref();
				}

			path = v->AsString()->CheckString();
			Unref(v);

#ifdef DEBUG
			DBG_LOG(DBG_LOGGING, "Path function for filter '%s' on stream '%s' return '%s'",
				filter->name.c_str(), stream->name.c_str(), path.c_str());
#endif
			}

		Stream::WriterPathPair wpp(filter->writer->AsEnum(), path);

		// See if we already have a writer for this path.
		Stream::WriterMap::iterator w = stream->writers.find(wpp);

		if ( w != stream->writers.end() &&
		     CheckFilterWriterConflict(w->second, filter) )
			{
			// Auto-correct path due to conflict over the writer/path pairs.
			string instantiator = w->second->instantiating_filter;
			string new_path;
			unsigned int i = 2;

			do {
				char num[32];
				snprintf(num, sizeof(num), "-%u", i++);
				new_path = path + num;
				wpp.second = new_path;
				w = stream->writers.find(wpp);
			} while ( w != stream->writers.end() &&
			          CheckFilterWriterConflict(w->second, filter) );

			Unref(filter->path_val);
			filter->path_val = new StringVal(new_path.c_str());

			reporter->Warning("Write using filter '%s' on path '%s' changed to"
			  " use new path '%s' to avoid conflict with filter '%s'",
			  filter->name.c_str(), path.c_str(), new_path.c_str(),
			  instantiator.c_str());

			path = filter->path = filter->path_val->AsString()->CheckString();
			}

		WriterFrontend* writer = 0;

		if ( w != stream->writers.end() )
			{
			// We know this writer already.
			writer = w->second->writer;
			}

		else
			{
			// No, need to create one.

			// Copy the fields for WriterFrontend::Init() as it
			// will take ownership.
			threading::Field** arg_fields = new threading::Field*[filter->num_fields];

			for ( int j = 0; j < filter->num_fields; ++j )
				arg_fields[j] = new threading::Field(*filter->fields[j]);

			WriterBackend::WriterInfo* info = new WriterBackend::WriterInfo;
			info->path = copy_string(path.c_str());
			info->network_time = network_time;

			HashKey* k;
			IterCookie* c = filter->config->AsTable()->InitForIteration();

			TableEntryVal* v;
			while ( (v = filter->config->AsTable()->NextEntry(k, c)) )
				{
				ListVal* index = filter->config->RecoverIndex(k);
				string key = index->Index(0)->AsString()->CheckString();
				string value = v->Value()->AsString()->CheckString();
				info->config.insert(std::make_pair(copy_string(key.c_str()), copy_string(value.c_str())));
				Unref(index);
				delete k;
				}

			// CreateWriter() will set the other fields in info.

			writer = CreateWriter(stream->id, filter->writer,
					      info, filter->num_fields, arg_fields, filter->local,
					      filter->remote, false, filter->name);

			if ( ! writer )
				{
				Unref(columns);
				return false;
				}
			}

		// Alright, can do the write now.

		threading::Value** vals = RecordToFilterVals(stream, filter, columns);

		// Write takes ownership of vals.
		assert(writer);
		writer->Write(filter->num_fields, vals);

#ifdef DEBUG
		DBG_LOG(DBG_LOGGING, "Wrote record to filter '%s' on stream '%s'",
			filter->name.c_str(), stream->name.c_str());
#endif
		}

#ifdef ENABLE_BROKER
	if ( stream->enable_remote &&
	     ! broker_mgr->Log(id, columns, stream->columns, stream->remote_flags) )
			stream->enable_remote = false;
#endif

	Unref(columns);

	if ( error )
		RemoveDisabledWriters(stream);

	return true;
	}

threading::Value* Manager::ValToLogVal(Val* val, BroType* ty)
	{
	if ( ! ty )
		ty = val->Type();

	if ( ! val )
		return new threading::Value(ty->Tag(), false);

	threading::Value* lval = new threading::Value(ty->Tag());

	switch ( lval->type ) {
	case TYPE_BOOL:
	case TYPE_INT:
		lval->val.int_val = val->InternalInt();
		break;

	case TYPE_ENUM:
		{
		const char* s =
			val->Type()->AsEnumType()->Lookup(val->InternalInt());

		if ( s )
			{
			lval->val.string_val.data = copy_string(s);
			lval->val.string_val.length = strlen(s);
			}

		else
			{
			val->Type()->Error("enum type does not contain value", val);
			lval->val.string_val.data = copy_string("");
			lval->val.string_val.length = 0;
			}
		break;
		}

	case TYPE_COUNT:
	case TYPE_COUNTER:
		lval->val.uint_val = val->InternalUnsigned();
		break;

	case TYPE_PORT:
		lval->val.port_val.port = val->AsPortVal()->Port();
		lval->val.port_val.proto = val->AsPortVal()->PortType();
		break;

	case TYPE_SUBNET:
		val->AsSubNet().ConvertToThreadingValue(&lval->val.subnet_val);
		break;

	case TYPE_ADDR:
		val->AsAddr().ConvertToThreadingValue(&lval->val.addr_val);
		break;

	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
		lval->val.double_val = val->InternalDouble();
		break;

	case TYPE_STRING:
		{
		const BroString* s = val->AsString();
		char* buf = new char[s->Len()];
		memcpy(buf, s->Bytes(), s->Len());

		lval->val.string_val.data = buf;
		lval->val.string_val.length = s->Len();
		break;
		}

	case TYPE_FILE:
		{
		const BroFile* f = val->AsFile();
		string s = f->Name();
		lval->val.string_val.data = copy_string(s.c_str());
		lval->val.string_val.length = s.size();
		break;
		}

	case TYPE_FUNC:
		{
		ODesc d;
		const Func* f = val->AsFunc();
		f->Describe(&d);
		const char* s = d.Description();
		lval->val.string_val.data = copy_string(s);
		lval->val.string_val.length = strlen(s);
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
		lval->val.set_val.vals = new threading::Value* [lval->val.set_val.size];

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
			new threading::Value* [lval->val.vector_val.size];

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

threading::Value** Manager::RecordToFilterVals(Stream* stream, Filter* filter,
				    RecordVal* columns)
	{
	threading::Value** vals = new threading::Value*[filter->num_fields];

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
				vals[i] = new threading::Value(filter->fields[i]->type, false);
				break;
				}
			}

		if ( val )
			vals[i] = ValToLogVal(val);
		}

	return vals;
	}

WriterFrontend* Manager::CreateWriter(EnumVal* id, EnumVal* writer, WriterBackend::WriterInfo* info,
				int num_fields, const threading::Field* const*  fields, bool local, bool remote, bool from_remote,
				const string& instantiating_filter)
	{
	Stream* stream = FindStream(id);

	if ( ! stream )
		// Don't know this stream.
		return 0;

	Stream::WriterMap::iterator w =
		stream->writers.find(Stream::WriterPathPair(writer->AsEnum(), info->path));

	if ( w != stream->writers.end() )
		// If we already have a writer for this. That's fine, we just
		// return it.
		return w->second->writer;

	WriterInfo* winfo = new WriterInfo;
	winfo->type = writer->Ref()->AsEnumVal();
	winfo->writer = 0;
	winfo->open_time = network_time;
	winfo->rotation_timer = 0;
	winfo->interval = 0;
	winfo->postprocessor = 0;
	winfo->info = info;
	winfo->from_remote = from_remote;
	winfo->instantiating_filter = instantiating_filter;

	// Search for a corresponding filter for the writer/path pair and use its
	// rotation settings.  If no matching filter is found, fall back on
	// looking up the logging framework's default rotation interval.
	bool found_filter_match = false;
	list<Filter*>::const_iterator it;

	for ( it = stream->filters.begin(); it != stream->filters.end(); ++it )
		{
		Filter* f = *it;
		if ( f->writer->AsEnum() == writer->AsEnum() &&
		     f->path == info->path )
			{
			found_filter_match = true;
			winfo->interval = f->interval;
			winfo->postprocessor = f->postprocessor;
			break;
			}
		}

	if ( ! found_filter_match )
		{
		ID* id = global_scope()->Lookup("Log::default_rotation_interval");
		assert(id);
		winfo->interval = id->ID_Val()->AsInterval();
		}

	stream->writers.insert(
		Stream::WriterMap::value_type(Stream::WriterPathPair(writer->AsEnum(), info->path),
		winfo));

	// Still need to set the WriterInfo's rotation parameters, which we
	// computed above.
	const char* base_time = log_rotate_base_time ?
		log_rotate_base_time->AsString()->CheckString() : 0;

	winfo->info->rotation_interval = winfo->interval;
	winfo->info->rotation_base = parse_rotate_base_time(base_time);

	winfo->writer = new WriterFrontend(*winfo->info, id, writer, local, remote);
	winfo->writer->Init(num_fields, fields);

	InstallRotationTimer(winfo);

	return winfo->writer;
	}

void Manager::DeleteVals(int num_fields, threading::Value** vals)
	{
	// Note this code is duplicated in WriterBackend::DeleteVals().
	for ( int i = 0; i < num_fields; i++ )
		delete vals[i];

	delete [] vals;
	}

bool Manager::Write(EnumVal* id, EnumVal* writer, string path, int num_fields,
		   threading::Value** vals)
	{
	Stream* stream = FindStream(id);

	if ( ! stream )
		{
		// Don't know this stream.
#ifdef DEBUG
		ODesc desc;
		id->Describe(&desc);
		DBG_LOG(DBG_LOGGING, "unknown stream %s in Manager::Write()",
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
		DBG_LOG(DBG_LOGGING, "unknown writer %s in Manager::Write()",
			desc.Description());
#endif
		DeleteVals(num_fields, vals);
		return false;
		}

	w->second->writer->Write(num_fields, vals);

	DBG_LOG(DBG_LOGGING,
		"Wrote pre-filtered record to path '%s' on stream '%s'",
		path.c_str(), stream->name.c_str());

	return true;
	}

void Manager::SendAllWritersTo(RemoteSerializer::PeerID peer)
	{
	for ( vector<Stream *>::iterator s = streams.begin(); s != streams.end(); ++s )
		{
		Stream* stream = (*s);

		if ( ! stream )
			continue;

		for ( Stream::WriterMap::iterator i = stream->writers.begin();
		      i != stream->writers.end(); i++ )
			{
			WriterFrontend* writer = i->second->writer;

			EnumVal writer_val(i->first.first, internal_type("Log::Writer")->AsEnumType());
			remote_serializer->SendLogCreateWriter(peer, (*s)->id,
							       &writer_val,
							       *i->second->info,
							       writer->NumFields(),
							       writer->Fields());
			}
		}
	}

bool Manager::SetBuf(EnumVal* id, bool enabled)
	{
	Stream* stream = FindStream(id);
	if ( ! stream )
		return false;

	for ( Stream::WriterMap::iterator i = stream->writers.begin();
	      i != stream->writers.end(); i++ )
		i->second->writer->SetBuf(enabled);

	RemoveDisabledWriters(stream);

	return true;
	}

bool Manager::Flush(EnumVal* id)
	{
	Stream* stream = FindStream(id);
	if ( ! stream )
		return false;

	if ( ! stream->enabled )
		return true;

	for ( Stream::WriterMap::iterator i = stream->writers.begin();
	      i != stream->writers.end(); i++ )
		i->second->writer->Flush(network_time);

	RemoveDisabledWriters(stream);

	return true;
	}

void Manager::Terminate()
	{
	for ( vector<Stream *>::iterator s = streams.begin(); s != streams.end(); ++s )
		{
		if ( ! *s )
			continue;

		for ( Stream::WriterMap::iterator i = (*s)->writers.begin();
		      i != (*s)->writers.end(); i++ )
			i->second->writer->Stop();
		}
	}

#ifdef ENABLE_BROKER

bool Manager::EnableRemoteLogs(EnumVal* stream_id, int flags)
	{
	auto stream = FindStream(stream_id);

	if ( ! stream )
		return false;

	stream->enable_remote = true;
	stream->remote_flags = flags;
	return true;
	}

bool Manager::DisableRemoteLogs(EnumVal* stream_id)
	{
	auto stream = FindStream(stream_id);

	if ( ! stream )
		return false;

	stream->enable_remote = false;
	return true;
	}

bool Manager::RemoteLogsAreEnabled(EnumVal* stream_id)
	{
	auto stream = FindStream(stream_id);

	if ( ! stream )
		return false;

	return stream->enable_remote;
	}

RecordType* Manager::StreamColumns(EnumVal* stream_id)
	{
	auto stream = FindStream(stream_id);

	if ( ! stream )
		return nullptr;

	return stream->columns;
	}

#endif

// Timer which on dispatching rotates the filter.
class RotationTimer : public Timer {
public:
	RotationTimer(double t, Manager::WriterInfo* arg_winfo, bool arg_rotate)
		: Timer(t, TIMER_ROTATE)
			{
			winfo = arg_winfo;
			rotate = arg_rotate;
			}

	~RotationTimer();

	void Dispatch(double t, int is_expire);

protected:
	Manager::WriterInfo* winfo;
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

void Manager::InstallRotationTimer(WriterInfo* winfo)
	{
	if ( terminating )
		return;

	if ( winfo->rotation_timer )
		{
		timer_mgr->Cancel(winfo->rotation_timer);
		winfo->rotation_timer = 0;
		}

	double rotation_interval = winfo->interval;

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

			double base = parse_rotate_base_time(base_time);
			double delta_t =
				calc_next_rotate(network_time, rotation_interval, base);

			winfo->rotation_timer =
				new RotationTimer(network_time + delta_t, winfo, true);
			}

		timer_mgr->Add(winfo->rotation_timer);

		DBG_LOG(DBG_LOGGING, "Scheduled rotation timer for %s to %.6f",
			winfo->writer->Name(), winfo->rotation_timer->Time());
		}
	}

void Manager::Rotate(WriterInfo* winfo)
	{
	DBG_LOG(DBG_LOGGING, "Rotating %s at %.6f",
		winfo->writer->Name(), network_time);

	// Build a temporary path for the writer to move the file to.
	struct tm tm;
	char buf[128];
	const char* const date_fmt = "%y-%m-%d_%H.%M.%S";
	time_t teatime = (time_t)winfo->open_time;

	localtime_r(&teatime, &tm);
	strftime(buf, sizeof(buf), date_fmt, &tm);

	// Trigger the rotation.
	const char* tmp = fmt("%s-%s", winfo->writer->Info().path, buf);
	winfo->writer->Rotate(tmp, winfo->open_time, network_time, terminating);

	++rotations_pending;
	}

bool Manager::FinishedRotation(WriterFrontend* writer, const char* new_name, const char* old_name,
		      double open, double close, bool success, bool terminating)
	{
	assert(writer);

	--rotations_pending;

	if ( ! success )
		{
		DBG_LOG(DBG_LOGGING, "Non-successful rotating writer '%s', file '%s' at %.6f,",
			writer->Name(), filename, network_time);
		return true;
		}

	DBG_LOG(DBG_LOGGING, "Finished rotating %s at %.6f, new name %s",
		writer->Name(), network_time, new_name);

	WriterInfo* winfo = FindWriter(writer);
	if ( ! winfo )
		return true;

	// Create the RotationInfo record.
	RecordVal* info = new RecordVal(BifType::Record::Log::RotationInfo);
	info->Assign(0, winfo->type->Ref());
	info->Assign(1, new StringVal(new_name));
	info->Assign(2, new StringVal(winfo->writer->Info().path));
	info->Assign(3, new Val(open, TYPE_TIME));
	info->Assign(4, new Val(close, TYPE_TIME));
	info->Assign(5, new Val(terminating, TYPE_BOOL));

	Func* func = winfo->postprocessor;
	if ( ! func )
		{
		ID* id = global_scope()->Lookup("Log::__default_rotation_postprocessor");
		assert(id);
		func = id->ID_Val()->AsFunc();
		}

	assert(func);

	// Call the postprocessor function.
	val_list vl(1);
	vl.append(info);

	int result = 0;

	Val* v = func->Call(&vl);
	if ( v )
		{
		result = v->AsBool();
		Unref(v);
		}

	return result;
	}
