// See the file "COPYING" in the main distribution directory for copyright.

#include "Manager.h"

#include <utility>

#include "Event.h"
#include "EventHandler.h"
#include "NetVar.h"
#include "Net.h"
#include "Type.h"
#include "File.h"
#include "input.h"
#include "IntrusivePtr.h"
#include "Func.h"

#include "broker/Manager.h"
#include "threading/Manager.h"
#include "threading/SerialTypes.h"

#include "Desc.h"
#include "WriterFrontend.h"
#include "WriterBackend.h"
#include "logging.bif.h"
#include "plugin/Plugin.h"
#include "plugin/Manager.h"

#include <broker/endpoint_info.hh>

using namespace std;
using namespace logging;

struct Manager::Filter {
	zeek::Val* fval;
	string name;
	zeek::EnumVal* id;
	zeek::Func* pred;
	zeek::Func* path_func;
	string path;
	zeek::Val* path_val;
	zeek::EnumVal* writer;
	zeek::TableVal* config;
	zeek::TableVal* field_name_map;
	string scope_sep;
	string ext_prefix;
	zeek::Func* ext_func;
	int num_ext_fields;
	bool local;
	bool remote;
	double interval;
	zeek::Func* postprocessor;

	int num_fields;
	threading::Field** fields;

	// Vector indexed by field number. Each element is a list of record
	// indices defining a path leading to the value across potential
	// sub-records.
	vector<list<int> > indices;

	~Filter();
};

struct Manager::WriterInfo {
	zeek::EnumVal* type;
	double open_time;
	Timer* rotation_timer;
	double interval;
	zeek::Func* postprocessor;
	WriterFrontend* writer;
	WriterBackend::WriterInfo* info;
	bool from_remote;
	bool hook_initialized;
	string instantiating_filter;
	};

struct Manager::Stream {
 	zeek::EnumVal* id;
	bool enabled;
	string name;
	zeek::RecordType* columns;
	EventHandlerPtr event;
	list<Filter*> filters;

	typedef pair<int, string> WriterPathPair;

	typedef map<WriterPathPair, WriterInfo*> WriterMap;

	WriterMap writers;	// Writers indexed by id/path pair.

	bool enable_remote;

	~Stream();
	};

Manager::Filter::~Filter()
	{
	Unref(fval);
	Unref(field_name_map);
	Unref(writer);
	Unref(id);

	for ( int i = 0; i < num_fields; ++i )
		delete fields[i];

	free(fields);

	Unref(path_val);
	Unref(config);
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

WriterBackend* Manager::CreateBackend(WriterFrontend* frontend, zeek::EnumVal* tag)
	{
	Component* c = Lookup(tag);

	if ( ! c )
		{
		reporter->Error("unknown writer type requested");
		return nullptr;
		}

	WriterBackend* backend = (*c->Factory())(frontend);
	assert(backend);

	return backend;
	}

Manager::Stream* Manager::FindStream(zeek::EnumVal* id)
	{
	unsigned int idx = id->AsEnum();

	if ( idx >= streams.size() || ! streams[idx] )
		return nullptr;

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

	return nullptr;
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

bool Manager::CreateStream(zeek::EnumVal* id, zeek::RecordVal* sval)
	{
	if ( ! same_type(sval->GetType(), zeek::BifType::Record::Log::Stream, false) )
		{
		reporter->Error("sval argument not of right type");
		return false;
		}

	zeek::RecordType* columns = sval->GetField("columns")
		->AsType()->AsTypeType()->GetType()->AsRecordType();

	bool log_attr_present = false;

	for ( int i = 0; i < columns->NumFields(); i++ )
		{
		if ( ! (columns->FieldDecl(i)->GetAttr(zeek::detail::ATTR_LOG)) )
		    continue;

		if ( ! threading::Value::IsCompatibleType(columns->GetFieldType(i).get()) )
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

	const auto& event_val = sval->GetField("ev");
	zeek::Func* event = event_val ? event_val->AsFunc() : nullptr;

	if ( event )
		{
		// Make sure the event is prototyped as expected.
		const auto& etype = event->GetType();

		if ( etype->Flavor() != zeek::FUNC_FLAVOR_EVENT )
			{
			reporter->Error("stream event is a function, not an event");
			return false;
			}

		const auto& args = etype->ParamList()->GetTypes();

		if ( args.size() != 1 )
			{
			reporter->Error("stream event must take a single argument");
			return false;
			}

		if ( ! same_type(args[0], columns) )
			{
			reporter->Error("stream event's argument type does not match column record type");
			return false;
			}
		}

	// Make sure the vector has an entries for all streams up to the one
	// given.

	unsigned int idx = id->AsEnum();

	while ( idx >= streams.size() )
		streams.push_back(nullptr);

	if ( streams[idx] )
		// We already know this one, delete the previous definition.
		delete streams[idx];

	// Create new stream.
	streams[idx] = new Stream;
	streams[idx]->id = id->Ref()->AsEnumVal();
	streams[idx]->enabled = true;
	streams[idx]->name = id->GetType()->AsEnumType()->Lookup(idx);
	streams[idx]->event = event ? event_registry->Lookup(event->Name()) : nullptr;
	streams[idx]->columns = columns->Ref()->AsRecordType();

	streams[idx]->enable_remote = zeek::id::find_val("Log::enable_remote_logging")->AsBool();

	DBG_LOG(DBG_LOGGING, "Created new logging stream '%s', raising event %s",
		streams[idx]->name.c_str(), event ? streams[idx]->event->Name() : "<none>");

	return true;
	}

bool Manager::RemoveStream(zeek::EnumVal* id)
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
	streams[idx] = nullptr;

	DBG_LOG(DBG_LOGGING, "Removed logging stream '%s'", sname.c_str());
	return true;
	}

bool Manager::EnableStream(zeek::EnumVal* id)
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

bool Manager::DisableStream(zeek::EnumVal* id)
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
bool Manager::TraverseRecord(Stream* stream, Filter* filter, zeek::RecordType* rt,
                             zeek::TableVal* include, zeek::TableVal* exclude,
                             const string& path, const list<int>& indices)
	{
	// Only include extensions for the outer record.
	int num_ext_fields = (indices.size() == 0) ? filter->num_ext_fields : 0;

	int i = 0;
	for ( int j = 0; j < num_ext_fields + rt->NumFields(); ++j )
		{
		zeek::RecordType* rtype;
		// If this is an ext field, set the rtype appropriately
		if ( j < num_ext_fields )
			{
			i = j;
			rtype = filter->ext_func->GetType()->Yield()->AsRecordType();
			}
		else
			{
			i = j - num_ext_fields;
			rtype = rt;
			}

		const auto& t = rtype->GetFieldType(i);

		// Ignore if &log not specified.
		if ( ! rtype->FieldDecl(i)->GetAttr(zeek::detail::ATTR_LOG) )
			continue;

		list<int> new_indices = indices;
		new_indices.push_back(i);

		// Build path name.
		string new_path;

		if ( ! path.size() )
			new_path = rtype->FieldName(i);
		else
			new_path = path + filter->scope_sep + rtype->FieldName(i);

		// Add the ext prefix if this is an ext field.
		if ( j < num_ext_fields )
			new_path = filter->ext_prefix + new_path;

		if ( t->InternalType() == zeek::TYPE_INTERNAL_OTHER )
			{
			if ( t->Tag() == zeek::TYPE_RECORD )
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

			else if ( t->Tag() == zeek::TYPE_TABLE &&
				  t->AsTableType()->IsSet() )
				{
				// That's ok, we handle it below.
				}

			else if ( t->Tag() == zeek::TYPE_VECTOR )
				{
				// That's ok, we handle it below.
				}

			else if ( t->Tag() == zeek::TYPE_FILE )
				{
				// That's ok, we handle it below.
				}

			else if ( t->Tag() == zeek::TYPE_FUNC )
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
			auto new_path_val = zeek::make_intrusive<zeek::StringVal>(new_path.c_str());
			bool result = (bool)include->FindOrDefault(new_path_val);

			if ( ! result )
				continue;
			}

		// If exclude fields are specified, do not only include if listed.
		if ( exclude )
			{
			auto new_path_val = zeek::make_intrusive<zeek::StringVal>(new_path.c_str());
			bool result = (bool)exclude->FindOrDefault(new_path_val);

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

		zeek::TypeTag st = zeek::TYPE_VOID;

		if ( t->Tag() == zeek::TYPE_TABLE )
			st = t->AsSetType()->GetIndices()->GetPureType()->Tag();

		else if ( t->Tag() == zeek::TYPE_VECTOR )
			st = t->AsVectorType()->Yield()->Tag();

		bool optional = (bool)rtype->FieldDecl(i)->GetAttr(zeek::detail::ATTR_OPTIONAL);

		filter->fields[filter->num_fields - 1] = new threading::Field(new_path.c_str(), nullptr, t->Tag(), st, optional);
		}

	return true;
	}

bool Manager::AddFilter(zeek::EnumVal* id, zeek::RecordVal* fval)
	{
	if ( ! same_type(fval->GetType(), zeek::BifType::Record::Log::Filter, false) )
		{
		reporter->Error("filter argument not of right type");
		return false;
		}

	Stream* stream = FindStream(id);
	if ( ! stream )
		return false;

	// Find the right writer type.
	auto writer = fval->GetFieldOrDefault<zeek::EnumVal>("writer");

	// Create a new Filter instance.

	auto name = fval->GetFieldOrDefault("name");
	auto pred = fval->GetFieldOrDefault("pred");
	auto path_func = fval->GetFieldOrDefault("path_func");
	auto log_local = fval->GetFieldOrDefault("log_local");
	auto log_remote = fval->GetFieldOrDefault("log_remote");
	auto interv = fval->GetFieldOrDefault("interv");
	auto postprocessor = fval->GetFieldOrDefault("postprocessor");
	auto config = fval->GetFieldOrDefault("config");
	auto field_name_map = fval->GetFieldOrDefault("field_name_map");
	auto scope_sep = fval->GetFieldOrDefault("scope_sep");
	auto ext_prefix = fval->GetFieldOrDefault("ext_prefix");
	auto ext_func = fval->GetFieldOrDefault("ext_func");

	Filter* filter = new Filter;
	filter->fval = fval->Ref();
	filter->name = name->AsString()->CheckString();
	filter->id = id->Ref()->AsEnumVal();
	filter->pred = pred ? pred->AsFunc() : nullptr;
	filter->path_func = path_func ? path_func->AsFunc() : nullptr;
	filter->writer = writer->Ref()->AsEnumVal();
	filter->local = log_local->AsBool();
	filter->remote = log_remote->AsBool();
	filter->interval = interv->AsInterval();
	filter->postprocessor = postprocessor ? postprocessor->AsFunc() : nullptr;
	filter->config = config->Ref()->AsTableVal();
	filter->field_name_map = field_name_map->Ref()->AsTableVal();
	filter->scope_sep = scope_sep->AsString()->CheckString();
	filter->ext_prefix = ext_prefix->AsString()->CheckString();
	filter->ext_func = ext_func ? ext_func->AsFunc() : nullptr;

	// Build the list of fields that the filter wants included, including
	// potentially rolling out fields.
	const auto& include = fval->GetField("include");
	const auto& exclude = fval->GetField("exclude");

	filter->num_ext_fields = 0;
	if ( filter->ext_func )
		{
		if ( filter->ext_func->GetType()->Yield()->Tag() == zeek::TYPE_RECORD )
			{
			filter->num_ext_fields = filter->ext_func->GetType()->Yield()->AsRecordType()->NumFields();
			}
		else if ( filter->ext_func->GetType()->Yield()->Tag() == zeek::TYPE_VOID )
			{
			// This is a special marker for the default no-implementation
			// of the ext_func and we'll allow it to slide.
			}
		else
			{
			reporter->Error("Return value of log_ext is not a record (got %s)",
			                zeek::type_name(filter->ext_func->GetType()->Yield()->Tag()));
			delete filter;
			return false;
			}
		}

	filter->num_fields = 0;
	filter->fields = nullptr;
	if ( ! TraverseRecord(stream, filter, stream->columns,
			      include ? include->AsTableVal() : nullptr,
			      exclude ? exclude->AsTableVal() : nullptr,
			      "", list<int>()) )
		{
		delete filter;
		return false;
		}

	// Get the path for the filter.
	auto path_val = fval->GetField("path");

	if ( path_val )
		{
		filter->path = path_val->AsString()->CheckString();
		filter->path_val = path_val.release();
		}

	else
		{
		// If no path is given, it's derived based upon the value returned by
		// the first call to the filter's path_func (during first write).
		filter->path_val = nullptr;
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
			field->name, zeek::type_name(field->type));
		}
#endif

	return true;
	}

bool Manager::RemoveFilter(zeek::EnumVal* id, zeek::StringVal* name)
	{
	return RemoveFilter(id, name->AsString()->CheckString());
	}

bool Manager::RemoveFilter(zeek::EnumVal* id, const string& name)
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

bool Manager::Write(zeek::EnumVal* id, zeek::RecordVal* columns_arg)
	{
	Stream* stream = FindStream(id);
	if ( ! stream )
		return false;

	if ( ! stream->enabled )
		return true;

	auto columns = columns_arg->CoerceTo({zeek::NewRef{}, stream->columns});

	if ( ! columns )
		{
		reporter->Error("incompatible log record type");
		return false;
		}

	// Raise the log event.
	if ( stream->event )
		mgr.Enqueue(stream->event, columns);

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
			int result = 1;
			auto v = filter->pred->Invoke(columns);

			if ( v )
				result = v->AsBool();

			if ( ! result )
				continue;
			}

		if ( filter->path_func )
			{
			zeek::ValPtr path_arg;

			if ( filter->path_val )
				path_arg = {zeek::NewRef{}, filter->path_val};
			else
				path_arg = zeek::val_mgr->EmptyString();

			zeek::ValPtr rec_arg;
			const auto& rt = filter->path_func->GetType()->Params()->GetFieldType("rec");

			if ( rt->Tag() == zeek::TYPE_RECORD )
				rec_arg = columns->CoerceTo(zeek::cast_intrusive<zeek::RecordType>(rt), true);
			else
				// Can be TYPE_ANY here.
				rec_arg = columns;

			auto v = filter->path_func->Invoke(zeek::IntrusivePtr{zeek::NewRef{}, id},
			                                   std::move(path_arg),
			                                   std::move(rec_arg));

			if ( ! v )
				return false;

			if ( v->GetType()->Tag() != zeek::TYPE_STRING )
				{
				reporter->Error("path_func did not return string");
				return false;
				}

			if ( ! filter->path_val )
				{
				filter->path = v->AsString()->CheckString();
				filter->path_val = v->Ref();
				}

			path = v->AsString()->CheckString();

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
			filter->path_val = new zeek::StringVal(new_path.c_str());

			reporter->Warning("Write using filter '%s' on path '%s' changed to"
			  " use new path '%s' to avoid conflict with filter '%s'",
			  filter->name.c_str(), path.c_str(), new_path.c_str(),
			  instantiator.c_str());

			path = filter->path = filter->path_val->AsString()->CheckString();
			}

		WriterBackend::WriterInfo* info = nullptr;
		WriterFrontend* writer = nullptr;

		if ( w != stream->writers.end() )
			{
			// We know this writer already.
			writer = w->second->writer;
			info = w->second->info;

			if ( ! w->second->hook_initialized )
				{
				auto wi = w->second;
				wi->hook_initialized = true;
				PLUGIN_HOOK_VOID(HOOK_LOG_INIT,
				                 HookLogInit(filter->writer->GetType()->AsEnumType()->Lookup(filter->writer->InternalInt()),
				                             wi->instantiating_filter, filter->local,
				                             filter->remote, *wi->info,
				                             filter->num_fields,
				                             filter->fields));
				}
			}

		else
			{
			// No, need to create one.

			// Copy the fields for WriterFrontend::Init() as it
			// will take ownership.
			threading::Field** arg_fields = new threading::Field*[filter->num_fields];

			for ( int j = 0; j < filter->num_fields; ++j )
				{
				// Rename fields if a field name map is set.
				if ( filter->field_name_map )
					{
					const char* name = filter->fields[j]->name;
					auto fn = zeek::make_intrusive<zeek::StringVal>(name);

					if ( const auto& val = filter->field_name_map->Find(fn) )
						{
						delete [] filter->fields[j]->name;
						filter->fields[j]->name = copy_string(val->AsStringVal()->CheckString());
						}
					}
				arg_fields[j] = new threading::Field(*filter->fields[j]);
				}

			info = new WriterBackend::WriterInfo;
			info->path = copy_string(path.c_str());
			info->network_time = network_time;

			HashKey* k;
			zeek::IterCookie* c = filter->config->AsTable()->InitForIteration();

			zeek::TableEntryVal* v;
			while ( (v = filter->config->AsTable()->NextEntry(k, c)) )
				{
				auto index = filter->config->RecreateIndex(*k);
				string key = index->Idx(0)->AsString()->CheckString();
				string value = v->GetVal()->AsString()->CheckString();
				info->config.insert(std::make_pair(copy_string(key.c_str()), copy_string(value.c_str())));
				delete k;
				}

			// CreateWriter() will set the other fields in info.

			writer = CreateWriter(stream->id, filter->writer,
					      info, filter->num_fields, arg_fields, filter->local,
					      filter->remote, false, filter->name);

			if ( ! writer )
				return false;
			}

		// Alright, can do the write now.

		threading::Value** vals = RecordToFilterVals(stream, filter, columns.get());

		if ( ! PLUGIN_HOOK_WITH_RESULT(HOOK_LOG_WRITE,
		                               HookLogWrite(filter->writer->GetType()->AsEnumType()->Lookup(filter->writer->InternalInt()),
		                                            filter->name, *info,
		                                            filter->num_fields,
		                                            filter->fields, vals),
		                               true) )
			{
			DeleteVals(filter->num_fields, vals);

#ifdef DEBUG
			DBG_LOG(DBG_LOGGING, "Hook prevented writing to filter '%s' on stream '%s'",
				filter->name.c_str(), stream->name.c_str());
#endif
			return true;
			}

		// Write takes ownership of vals.
		assert(writer);
		writer->Write(filter->num_fields, vals);

#ifdef DEBUG
		DBG_LOG(DBG_LOGGING, "Wrote record to filter '%s' on stream '%s'",
			filter->name.c_str(), stream->name.c_str());
#endif
		}

	return true;
	}

threading::Value* Manager::ValToLogVal(zeek::Val* val, zeek::Type* ty)
	{
	if ( ! ty )
		ty = val->GetType().get();

	if ( ! val )
		return new threading::Value(ty->Tag(), false);

	threading::Value* lval = new threading::Value(ty->Tag());

	switch ( lval->type ) {
	case zeek::TYPE_BOOL:
	case zeek::TYPE_INT:
		lval->val.int_val = val->InternalInt();
		break;

	case zeek::TYPE_ENUM:
		{
		const char* s =
			val->GetType()->AsEnumType()->Lookup(val->InternalInt());

		if ( s )
			{
			lval->val.string_val.data = copy_string(s);
			lval->val.string_val.length = strlen(s);
			}

		else
			{
			val->GetType()->Error("enum type does not contain value", val);
			lval->val.string_val.data = copy_string("");
			lval->val.string_val.length = 0;
			}
		break;
		}

	case zeek::TYPE_COUNT:
	case zeek::TYPE_COUNTER:
		lval->val.uint_val = val->InternalUnsigned();
		break;

	case zeek::TYPE_PORT:
		lval->val.port_val.port = val->AsPortVal()->Port();
		lval->val.port_val.proto = val->AsPortVal()->PortType();
		break;

	case zeek::TYPE_SUBNET:
		val->AsSubNet().ConvertToThreadingValue(&lval->val.subnet_val);
		break;

	case zeek::TYPE_ADDR:
		val->AsAddr().ConvertToThreadingValue(&lval->val.addr_val);
		break;

	case zeek::TYPE_DOUBLE:
	case zeek::TYPE_TIME:
	case zeek::TYPE_INTERVAL:
		lval->val.double_val = val->InternalDouble();
		break;

	case zeek::TYPE_STRING:
		{
		const zeek::String* s = val->AsString();
		char* buf = new char[s->Len()];
		memcpy(buf, s->Bytes(), s->Len());

		lval->val.string_val.data = buf;
		lval->val.string_val.length = s->Len();
		break;
		}

	case zeek::TYPE_FILE:
		{
		const BroFile* f = val->AsFile();
		string s = f->Name();
		lval->val.string_val.data = copy_string(s.c_str());
		lval->val.string_val.length = s.size();
		break;
		}

	case zeek::TYPE_FUNC:
		{
		ODesc d;
		const zeek::Func* f = val->AsFunc();
		f->Describe(&d);
		const char* s = d.Description();
		lval->val.string_val.data = copy_string(s);
		lval->val.string_val.length = strlen(s);
		break;
		}

	case zeek::TYPE_TABLE:
		{
		auto set = val->AsTableVal()->ToPureListVal();
		if ( ! set )
			// ToPureListVal has reported an internal warning
			// already. Just keep going by making something up.
			set = zeek::make_intrusive<zeek::ListVal>(zeek::TYPE_INT);

		lval->val.set_val.size = set->Length();
		lval->val.set_val.vals = new threading::Value* [lval->val.set_val.size];

		for ( int i = 0; i < lval->val.set_val.size; i++ )
			lval->val.set_val.vals[i] = ValToLogVal(set->Idx(i).get());

		break;
		}

	case zeek::TYPE_VECTOR:
		{
		zeek::VectorVal* vec = val->AsVectorVal();
		lval->val.vector_val.size = vec->Size();
		lval->val.vector_val.vals =
			new threading::Value* [lval->val.vector_val.size];

		for ( int i = 0; i < lval->val.vector_val.size; i++ )
			{
			lval->val.vector_val.vals[i] =
				ValToLogVal(vec->At(i).get(),
					    vec->GetType()->Yield().get());
			}

		break;
		}

	default:
		reporter->InternalError("unsupported type %s for log_write", zeek::type_name(lval->type));
	}

	return lval;
	}

threading::Value** Manager::RecordToFilterVals(Stream* stream, Filter* filter,
                                               zeek::RecordVal* columns)
	{
	zeek::RecordValPtr ext_rec;

	if ( filter->num_ext_fields > 0 )
		{
		auto res = filter->ext_func->Invoke(zeek::IntrusivePtr{zeek::NewRef{}, filter->path_val});

		if ( res )
			ext_rec = {zeek::AdoptRef{}, res.release()->AsRecordVal()};
		}

	threading::Value** vals = new threading::Value*[filter->num_fields];

	for ( int i = 0; i < filter->num_fields; ++i )
		{
		zeek::Val* val;
		if ( i < filter->num_ext_fields )
			{
			if ( ! ext_rec )
				{
				// executing function did not return record. Send empty for all vals.
				vals[i] = new threading::Value(filter->fields[i]->type, false);
				continue;
				}

			val = ext_rec.get();
			}
		else
			val = columns;

		// For each field, first find the right value, which can
		// potentially be nested inside other records.
		list<int>& indices = filter->indices[i];

		for ( list<int>::iterator j = indices.begin(); j != indices.end(); ++j )
			{
			val = val->AsRecordVal()->GetField(*j).get();

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

bool Manager::CreateWriterForRemoteLog(zeek::EnumVal* id, zeek::EnumVal* writer, WriterBackend::WriterInfo* info,
			   int num_fields, const threading::Field* const* fields)
	{
	return CreateWriter(id, writer, info, num_fields, fields, true, false, true);
	}

static void delete_info_and_fields(WriterBackend::WriterInfo* info, int num_fields, const threading::Field* const* fields)
	{
	for ( int i = 0; i < num_fields; i++ )
		delete fields[i];

	delete [] fields;
	delete info;
	}

WriterFrontend* Manager::CreateWriter(zeek::EnumVal* id, zeek::EnumVal* writer, WriterBackend::WriterInfo* info,
                                      int num_fields, const threading::Field* const* fields, bool local,
                                      bool remote, bool from_remote, const string& instantiating_filter)
	{
	WriterFrontend* result = nullptr;

	Stream* stream = FindStream(id);

	if ( ! stream )
		{
		// Don't know this stream.
		delete_info_and_fields(info, num_fields, fields);
		return nullptr;
		}

	Stream::WriterMap::iterator w =
		stream->writers.find(Stream::WriterPathPair(writer->AsEnum(), info->path));

	if ( w != stream->writers.end() )
		{
		// If we already have a writer for this. That's fine, we just
		// return it.
		delete_info_and_fields(info, num_fields, fields);
		return w->second->writer;
		}

	WriterInfo* winfo = new WriterInfo;
	winfo->type = writer->Ref()->AsEnumVal();
	winfo->writer = nullptr;
	winfo->open_time = network_time;
	winfo->rotation_timer = nullptr;
	winfo->interval = 0;
	winfo->postprocessor = nullptr;
	winfo->info = info;
	winfo->from_remote = from_remote;
	winfo->hook_initialized = false;
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

			if ( f->postprocessor )
				{
				delete [] winfo->info->post_proc_func;
				winfo->info->post_proc_func = copy_string(f->postprocessor->Name());
				}

			break;
			}
		}

	if ( ! found_filter_match )
		{
		const auto& id = zeek::detail::global_scope()->Find("Log::default_rotation_interval");
		assert(id);
		winfo->interval = id->GetVal()->AsInterval();

		if ( winfo->info->post_proc_func &&
		     strlen(winfo->info->post_proc_func) )
			{
			auto func = zeek::id::find_func(winfo->info->post_proc_func);

			if ( func )
				winfo->postprocessor = func.get();
			else
				reporter->Warning("failed log postprocessor function lookup: %s\n",
				                  winfo->info->post_proc_func);
			}
		}

	stream->writers.insert(
		Stream::WriterMap::value_type(Stream::WriterPathPair(writer->AsEnum(), info->path),
		winfo));

	// Still need to set the WriterInfo's rotation parameters, which we
	// computed above.
	static auto log_rotate_base_time = zeek::id::find_val<zeek::StringVal>("log_rotate_base_time");
	static auto base_time = log_rotate_base_time->AsString()->CheckString();

	winfo->info->rotation_interval = winfo->interval;
	winfo->info->rotation_base = parse_rotate_base_time(base_time);

	winfo->writer = new WriterFrontend(*winfo->info, id, writer, local, remote);
	winfo->writer->Init(num_fields, fields);

	if ( ! from_remote )
		{
		winfo->hook_initialized = true;
		PLUGIN_HOOK_VOID(HOOK_LOG_INIT,
		                 HookLogInit(writer->GetType()->AsEnumType()->Lookup(writer->InternalInt()),
		                             instantiating_filter, local, remote,
		                             *winfo->info, num_fields, fields));
		}

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

bool Manager::WriteFromRemote(zeek::EnumVal* id, zeek::EnumVal* writer, const string& path, int num_fields,
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

void Manager::SendAllWritersTo(const broker::endpoint_info& ei)
	{
	auto et = zeek::id::find_type("Log::Writer")->AsEnumType();

	for ( vector<Stream *>::iterator s = streams.begin(); s != streams.end(); ++s )
		{
		Stream* stream = (*s);

		if ( ! (stream && stream->enable_remote) )
			continue;


		for ( Stream::WriterMap::iterator i = stream->writers.begin();
		      i != stream->writers.end(); i++ )
			{
			WriterFrontend* writer = i->second->writer;
			const auto& writer_val = et->GetVal(i->first.first);
			broker_mgr->PublishLogCreate((*s)->id,
						     writer_val.get(),
						     *i->second->info,
						     writer->NumFields(),
						     writer->Fields(),
						     ei);
			}
		}
	}

bool Manager::SetBuf(zeek::EnumVal* id, bool enabled)
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

bool Manager::Flush(zeek::EnumVal* id)
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

bool Manager::EnableRemoteLogs(zeek::EnumVal* stream_id)
	{
	auto stream = FindStream(stream_id);

	if ( ! stream )
		return false;

	stream->enable_remote = true;
	return true;
	}

bool Manager::DisableRemoteLogs(zeek::EnumVal* stream_id)
	{
	auto stream = FindStream(stream_id);

	if ( ! stream )
		return false;

	stream->enable_remote = false;
	return true;
	}

bool Manager::RemoteLogsAreEnabled(zeek::EnumVal* stream_id)
	{
	auto stream = FindStream(stream_id);

	if ( ! stream )
		return false;

	return stream->enable_remote;
	}

zeek::RecordType* Manager::StreamColumns(zeek::EnumVal* stream_id)
	{
	auto stream = FindStream(stream_id);

	if ( ! stream )
		return nullptr;

	return stream->columns;
	}

// Timer which on dispatching rotates the filter.
class RotationTimer final : public Timer {
public:
	RotationTimer(double t, Manager::WriterInfo* arg_winfo, bool arg_rotate)
		: Timer(t, TIMER_ROTATE)
			{
			winfo = arg_winfo;
			rotate = arg_rotate;
			}

	~RotationTimer() override;

	void Dispatch(double t, bool is_expire) override;

protected:
	Manager::WriterInfo* winfo;
	bool rotate;
};

RotationTimer::~RotationTimer()
	{
	if ( winfo->rotation_timer == this )
		winfo->rotation_timer = nullptr;
	}

void RotationTimer::Dispatch(double t, bool is_expire)
	{
	winfo->rotation_timer = nullptr;

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
		winfo->rotation_timer = nullptr;
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

			static auto log_rotate_base_time = zeek::id::find_val<zeek::StringVal>("log_rotate_base_time");
			static auto base_time = log_rotate_base_time->AsString()->CheckString();

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

std::string Manager::FormatRotationTime(time_t t)
	{
	struct tm tm;
	char buf[128];
	const char* const date_fmt = "%y-%m-%d_%H.%M.%S";
	localtime_r(&t, &tm);
	strftime(buf, sizeof(buf), date_fmt, &tm);
	return buf;
	}

std::string Manager::FormatRotationPath(std::string_view path, time_t t)
	{
	auto rot_str = FormatRotationTime(t);
	return fmt("%.*s-%s",
	           static_cast<int>(path.size()), path.data(), rot_str.data());
	}

void Manager::Rotate(WriterInfo* winfo)
	{
	DBG_LOG(DBG_LOGGING, "Rotating %s at %.6f",
		winfo->writer->Name(), network_time);

	// Build a temporary path for the writer to move the file to.
	auto tmp = FormatRotationPath(winfo->writer->Info().path,
	                              (time_t)winfo->open_time);
	winfo->writer->Rotate(tmp.data(), winfo->open_time, network_time, terminating);

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
	auto info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::Log::RotationInfo);
	info->Assign(0, {zeek::NewRef{}, winfo->type});
	info->Assign(1, zeek::make_intrusive<zeek::StringVal>(new_name));
	info->Assign(2, zeek::make_intrusive<zeek::StringVal>(winfo->writer->Info().path));
	info->Assign(3, zeek::make_intrusive<zeek::TimeVal>(open));
	info->Assign(4, zeek::make_intrusive<zeek::TimeVal>(close));
	info->Assign(5, zeek::val_mgr->Bool(terminating));

	zeek::Func* func = winfo->postprocessor;
	if ( ! func )
		{
		const auto& id = zeek::detail::global_scope()->Find("Log::__default_rotation_postprocessor");
		assert(id);
		func = id->GetVal()->AsFunc();
		}

	assert(func);

	// Call the postprocessor function.
	int result = 0;

	auto v = func->Invoke(std::move(info));
	if ( v )
		result = v->AsBool();

	return result;
	}
