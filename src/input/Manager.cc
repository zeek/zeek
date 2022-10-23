// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/input/Manager.h"

#include <string>
#include <utility>

#include "zeek/CompHash.h"
#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/EventHandler.h"
#include "zeek/Expr.h"
#include "zeek/Func.h"
#include "zeek/NetVar.h"
#include "zeek/RunState.h"
#include "zeek/file_analysis/Manager.h"
#include "zeek/input/ReaderBackend.h"
#include "zeek/input/ReaderFrontend.h"
#include "zeek/input/input.bif.h"
#include "zeek/module_util.h"
#include "zeek/threading/SerialTypes.h"

using namespace std;
using zeek::threading::Field;
using zeek::threading::Value;

namespace zeek::input
	{

/**
 * InputHashes are used as Dictionaries to store the value and index hashes
 * for all lines currently stored in a table. Index hash is stored as
 * HashKey*, because it is thrown into other Zeek functions that need the
 * complex structure of it. For everything we do (with values), we just take
 * the hash_t value and compare it directly with "=="
 */
struct InputHash
	{
	zeek::detail::hash_t valhash;
	zeek::detail::HashKey* idxkey;
	~InputHash();
	};

InputHash::~InputHash()
	{
	delete idxkey;
	}

static void input_hash_delete_func(void* val)
	{
	InputHash* h = (InputHash*)val;
	delete h;
	}

/**
 * Base stuff that every stream can do.
 */
class Manager::Stream
	{
public:
	string name;
	bool removed;

	StreamType stream_type; // to distinguish between event and table streams

	EnumVal* type;
	ReaderFrontend* reader;
	TableVal* config;
	EventHandlerPtr error_event;

	RecordVal* description;

	virtual ~Stream();

protected:
	Stream(StreamType t);
	};

Manager::Stream::Stream(StreamType t)
	: name(), removed(), stream_type(t), type(), reader(), config(), error_event(), description()
	{
	}

Manager::Stream::~Stream()
	{
	Unref(type);
	Unref(description);
	Unref(config);
	delete reader;
	}

class Manager::TableStream final : public Manager::Stream
	{
public:
	unsigned int num_idx_fields;
	unsigned int num_val_fields;
	bool want_record;

	TableVal* tab;
	RecordType* rtype;
	RecordType* itype;

	PDict<InputHash>* currDict;
	PDict<InputHash>* lastDict;

	Func* pred;

	EventHandlerPtr event;

	TableStream();
	~TableStream() override;
	};

class Manager::EventStream final : public Manager::Stream
	{
public:
	EventHandlerPtr event;

	RecordType* fields;
	unsigned int num_fields;

	bool want_record;
	EventStream();
	~EventStream() override;
	};

class Manager::AnalysisStream final : public Manager::Stream
	{
public:
	string file_id;

	AnalysisStream();
	~AnalysisStream() override;
	};

Manager::TableStream::TableStream()
	: Manager::Stream::Stream(TABLE_STREAM), num_idx_fields(), num_val_fields(), want_record(),
	  tab(), rtype(), itype(), currDict(), lastDict(), pred(), event()
	{
	}

Manager::EventStream::EventStream()
	: Manager::Stream::Stream(EVENT_STREAM), event(), fields(), num_fields(), want_record()
	{
	}

Manager::EventStream::~EventStream()
	{
	if ( fields )
		Unref(fields);
	}

Manager::TableStream::~TableStream()
	{
	if ( tab )
		Unref(tab);

	if ( itype )
		Unref(itype);

	if ( rtype ) // can be 0 for sets
		Unref(rtype);

	if ( currDict )
		{
		currDict->Clear();
		delete currDict;
		}

	if ( lastDict )
		{
		lastDict->Clear();
		;
		delete lastDict;
		}
	}

Manager::AnalysisStream::AnalysisStream() : Manager::Stream::Stream(ANALYSIS_STREAM), file_id() { }

Manager::AnalysisStream::~AnalysisStream() { }

Manager::Manager() : plugin::ComponentManager<input::Component>("Input", "Reader")
	{
	end_of_data = event_registry->Register("Input::end_of_data");
	}

Manager::~Manager()
	{
	for ( map<ReaderFrontend*, Stream*>::iterator s = readers.begin(); s != readers.end(); ++s )
		{
		delete s->second;
		delete s->first;
		}
	}

ReaderBackend* Manager::CreateBackend(ReaderFrontend* frontend, EnumVal* tag)
	{
	Component* c = Lookup(tag);

	if ( ! c )
		{
		reporter->Error(
			"The reader that was requested was not found and could not be initialized.");
		return nullptr;
		}

	ReaderBackend* backend = (*c->Factory())(frontend);
	assert(backend);

	return backend;
	}

// Create a new input reader object to be used at whomevers leisure later on.
bool Manager::CreateStream(Stream* info, RecordVal* description)
	{
	RecordType* rtype = description->GetType()->AsRecordType();
	if ( ! (same_type(rtype, BifType::Record::Input::TableDescription, false) ||
	        same_type(rtype, BifType::Record::Input::EventDescription, false) ||
	        same_type(rtype, BifType::Record::Input::AnalysisDescription, false)) )
		{
		reporter->Error("Stream description argument not of right type for new input stream");
		return false;
		}

	string name = description->GetFieldOrDefault("name")->AsString()->CheckString();

	if ( Stream* i = FindStream(name) )
		{
		reporter->Error("Trying create already existing input stream %s", name.c_str());
		return false;
		}

	auto reader = description->GetFieldOrDefault("reader");

	// get the source ...
	auto source_val = description->GetFieldOrDefault("source");
	const String* bsource = source_val->AsString();
	string source((const char*)bsource->Bytes(), bsource->Len());

	ReaderBackend::ReaderInfo rinfo;
	rinfo.source = util::copy_string(source.c_str());
	rinfo.name = util::copy_string(name.c_str());

	auto mode_val = description->GetFieldOrDefault("mode");
	auto mode = mode_val->AsEnumVal();
	switch ( mode->InternalInt() )
		{
		case 0:
			rinfo.mode = MODE_MANUAL;
			break;

		case 1:
			rinfo.mode = MODE_REREAD;
			break;

		case 2:
			rinfo.mode = MODE_STREAM;
			break;

		default:
			reporter->InternalWarning("unknown input reader mode");
			return false;
		}

	auto config = description->GetFieldOrDefault("config");
	info->config = config.release()->AsTableVal();

		{
		// create config mapping in ReaderInfo. Has to be done before the construction of
		// reader_obj.
		auto* info_config_table = info->config->AsTable();
		for ( const auto& icte : *info_config_table )
			{
			auto k = icte.GetHashKey();
			auto* v = icte.value;

			auto index = info->config->RecreateIndex(*k);
			string key = index->Idx(0)->AsString()->CheckString();
			string value = v->GetVal()->AsString()->CheckString();
			rinfo.config.insert(
				std::make_pair(util::copy_string(key.c_str()), util::copy_string(value.c_str())));
			}
		}

	ReaderFrontend* reader_obj = new ReaderFrontend(rinfo, reader->AsEnumVal());
	assert(reader_obj);

	info->reader = reader_obj;
	info->type = reader.release()->AsEnumVal();
	info->name = name;

	Ref(description);
	info->description = description;

	DBG_LOG(DBG_INPUT, "Successfully created new input stream %s", name.c_str());

	return true;
	}

bool Manager::CreateEventStream(RecordVal* fval)
	{
	RecordType* rtype = fval->GetType()->AsRecordType();
	if ( ! same_type(rtype, BifType::Record::Input::EventDescription, false) )
		{
		reporter->Error("EventDescription argument not of right type");
		return false;
		}

	string stream_name = fval->GetFieldOrDefault("name")->AsString()->CheckString();

	auto fields_val = fval->GetFieldOrDefault("fields");
	RecordType* fields = fields_val->AsType()->AsTypeType()->GetType()->AsRecordType();

	auto want_record = fval->GetFieldOrDefault("want_record");

	auto ev_val = fval->GetFieldOrDefault("ev");
	Func* event = ev_val->AsFunc();

	const auto& etype = event->GetType();

	bool allow_file_func = false;

	if ( etype->Flavor() != FUNC_FLAVOR_EVENT )
		{
		reporter->Error("Input stream %s: Stream event is a function, not an event",
		                stream_name.c_str());
		return false;
		}

	const auto& args = etype->ParamList()->GetTypes();

	if ( args.size() < 2 )
		{
		reporter->Error("Input stream %s: Event does not take enough arguments",
		                stream_name.c_str());
		return false;
		}

	if ( ! same_type(args[1], BifType::Enum::Input::Event, false) )
		{
		reporter->Error("Input stream %s: Event's second attribute must be of type Input::Event",
		                stream_name.c_str());
		return false;
		}

	if ( ! same_type(args[0], BifType::Record::Input::EventDescription, false) )
		{
		reporter->Error(
			"Input stream %s: Event's first attribute must be of type Input::EventDescription",
			stream_name.c_str());
		return false;
		}

	if ( want_record->InternalInt() == 0 )
		{
		if ( static_cast<int>(args.size()) != fields->NumFields() + 2 )
			{
			reporter->Error("Input stream %s: Event has wrong number of arguments",
			                stream_name.c_str());
			return false;
			}

		for ( int i = 0; i < fields->NumFields(); i++ )
			{
			if ( ! same_type(args[i + 2], fields->GetFieldType(i)) )
				{
				ODesc desc1;
				ODesc desc2;
				args[i + 2]->Describe(&desc1);
				fields->GetFieldType(i)->Describe(&desc2);

				reporter->Error("Input stream %s: Incompatible type for event in field %d. Need "
				                "type '%s':%s, got '%s':%s",
				                stream_name.c_str(), i + 3,
				                type_name(fields->GetFieldType(i)->Tag()), desc2.Description(),
				                type_name(args[i + 2]->Tag()), desc1.Description());

				return false;
				}
			}
		}

	else if ( want_record->InternalInt() == 1 )
		{
		if ( args.size() != 3 )
			{
			reporter->Error("Input stream %s: Event has wrong number of arguments",
			                stream_name.c_str());
			return false;
			}

		if ( ! same_type(args[2], fields) )
			{
			ODesc desc1;
			ODesc desc2;
			args[2]->Describe(&desc1);
			fields->Describe(&desc2);
			reporter->Error(
				"Input stream %s: Incompatible type '%s':%s for event, which needs type '%s':%s\n",
				stream_name.c_str(), type_name(args[2]->Tag()), desc1.Description(),
				type_name(fields->Tag()), desc2.Description());
			return false;
			}

		allow_file_func = BifConst::Input::accept_unsupported_types;
		}

	else
		assert(false);

	auto error_event_val = fval->GetFieldOrDefault("error_ev");
	Func* error_event = error_event_val ? error_event_val->AsFunc() : nullptr;

	if ( ! CheckErrorEventTypes(stream_name, error_event, false) )
		return false;

	vector<Field*> fieldsV; // vector, because UnrollRecordType needs it

	bool status = (! UnrollRecordType(&fieldsV, fields, "", allow_file_func));

	if ( status )
		{
		reporter->Error("Input stream %s: Problem unrolling", stream_name.c_str());
		for ( auto& f : fieldsV )
			delete f;
		return false;
		}

	EventStream* stream = new EventStream();

	bool res = CreateStream(stream, fval);
	if ( ! res )
		{
		delete stream;
		for ( auto& f : fieldsV )
			delete f;
		return false;
		}

	Field** logf = new Field*[fieldsV.size()];
	for ( size_t i = 0; i < fieldsV.size(); i++ )
		logf[i] = fieldsV[i];

	stream->num_fields = fieldsV.size();
	stream->fields = fields->Ref()->AsRecordType();
	stream->event = event_registry->Lookup(event->Name());
	stream->error_event = error_event ? event_registry->Lookup(error_event->Name()) : nullptr;
	stream->want_record = (want_record->InternalInt() == 1);

	assert(stream->reader);

	stream->reader->Init(stream->num_fields, logf);

	readers[stream->reader] = stream;

	DBG_LOG(DBG_INPUT, "Successfully created event stream %s", stream->name.c_str());

	return true;
	}

bool Manager::CreateTableStream(RecordVal* fval)
	{
	RecordType* rtype = fval->GetType()->AsRecordType();
	if ( ! same_type(rtype, BifType::Record::Input::TableDescription, false) )
		{
		reporter->Error("TableDescription argument not of right type");
		return false;
		}

	string stream_name = fval->GetFieldOrDefault("name")->AsString()->CheckString();

	auto pred = fval->GetFieldOrDefault("pred");
	auto idx_val = fval->GetFieldOrDefault("idx");
	RecordType* idx = idx_val->AsType()->AsTypeType()->GetType()->AsRecordType();

	RecordTypePtr val;
	auto val_val = fval->GetFieldOrDefault("val");

	if ( val_val )
		val = val_val->AsType()->AsTypeType()->GetType<RecordType>();

	auto dst = fval->GetFieldOrDefault("destination");

	// check if index fields match table description
	size_t num = idx->NumFields();
	const auto& tl = dst->GetType()->AsTableType()->GetIndexTypes();
	size_t j;

	for ( j = 0; j < tl.size(); ++j )
		{
		if ( j >= num )
			{
			reporter->Error("Input stream %s: Table type has more indexes than index definition",
			                stream_name.c_str());
			return false;
			}

		if ( ! same_type(idx->GetFieldType(j), tl[j]) )
			{
			ODesc desc1;
			ODesc desc2;
			idx->GetFieldType(j)->Describe(&desc1);
			tl[j]->Describe(&desc2);

			reporter->Error("Input stream %s: Table type does not match index type. Need type "
			                "'%s':%s, got '%s':%s",
			                stream_name.c_str(), type_name(idx->GetFieldType(j)->Tag()),
			                desc1.Description(), type_name(tl[j]->Tag()), desc2.Description());

			return false;
			}
		}

	if ( num != j )
		{
		reporter->Error("Input stream %s: Table has less elements than index definition",
		                stream_name.c_str());
		return false;
		}

	auto want_record = fval->GetFieldOrDefault("want_record");
	auto destination_is_set = dst->GetType()->IsSet();

	if ( val )
		{
		if ( destination_is_set )
			{
			reporter->Error("Input stream %s: 'destination' field is a set, "
			                "but the 'val' field was also specified "
			                "(did you mean to use a table instead of a set?)",
			                stream_name.data());
			return false;
			}
		else
			{
			const auto& table_yield = dst->GetType()->AsTableType()->Yield();
			const auto& compare_type = want_record->InternalInt() == 0 ? val->GetFieldType(0) : val;

			if ( ! same_type(table_yield, compare_type) )
				{
				ODesc desc1;
				ODesc desc2;
				compare_type->Describe(&desc1);
				table_yield->Describe(&desc2);
				reporter->Error("Input stream %s: Table type does not match value type. Need type "
				                "'%s', got '%s'",
				                stream_name.c_str(), desc1.Description(), desc2.Description());
				return false;
				}
			}
		}
	else
		{
		if ( ! destination_is_set )
			{
			reporter->Error("Input stream %s: 'destination' field is a table,"
			                " but 'val' field is not provided"
			                " (did you mean to use a set instead of a table?)",
			                stream_name.c_str());
			return false;
			}
		}

	auto event_val = fval->GetFieldOrDefault("ev");
	Func* event = event_val ? event_val->AsFunc() : nullptr;

	if ( event )
		{
		const auto& etype = event->GetType();

		if ( etype->Flavor() != FUNC_FLAVOR_EVENT )
			{
			reporter->Error("Input stream %s: Stream event is a function, not an event",
			                stream_name.c_str());
			return false;
			}

		const auto& args = etype->ParamList()->GetTypes();
		size_t required_arg_count = destination_is_set ? 3 : 4;

		if ( args.size() != required_arg_count )
			{
			reporter->Error("Input stream %s: Table event must take %zu arguments",
			                stream_name.c_str(), required_arg_count);
			return false;
			}

		if ( ! same_type(args[0], BifType::Record::Input::TableDescription, false) )
			{
			reporter->Error("Input stream %s: Table event's first attribute must be of type "
			                "Input::TableDescription",
			                stream_name.c_str());
			return false;
			}

		if ( ! same_type(args[1], BifType::Enum::Input::Event, false) )
			{
			reporter->Error(
				"Input stream %s: Table event's second attribute must be of type Input::Event",
				stream_name.c_str());
			return false;
			}

		if ( ! same_type(args[2], idx) )
			{
			ODesc desc1;
			ODesc desc2;
			idx->Describe(&desc1);
			args[2]->Describe(&desc2);
			reporter->Error(
				"Input stream %s: Table event's index attributes do not match. Need '%s', got '%s'",
				stream_name.c_str(), desc1.Description(), desc2.Description());
			return false;
			}

		if ( ! destination_is_set )
			{
			if ( want_record->InternalInt() == 1 && val && ! same_type(args[3], val) )
				{
				ODesc desc1;
				ODesc desc2;
				val->Describe(&desc1);
				args[3]->Describe(&desc2);
				reporter->Error("Input stream %s: Table event's value attributes do not match. "
				                "Need '%s', got '%s'",
				                stream_name.c_str(), desc1.Description(), desc2.Description());
				return false;
				}
			else if ( want_record->InternalInt() == 0 && val &&
			          ! same_type(args[3], val->GetFieldType(0)) )
				{
				ODesc desc1;
				ODesc desc2;
				val->GetFieldType(0)->Describe(&desc1);
				args[3]->Describe(&desc2);
				reporter->Error("Input stream %s: Table event's value attribute does not match. "
				                "Need '%s', got '%s'",
				                stream_name.c_str(), desc1.Description(), desc2.Description());
				return false;
				}
			else if ( ! val )
				{
				reporter->Error("Encountered a null value when creating a table stream");
				}
			}

		assert(want_record->InternalInt() == 1 || want_record->InternalInt() == 0);
		}

	auto error_event_val = fval->GetFieldOrDefault("error_ev");
	Func* error_event = error_event_val ? error_event_val->AsFunc() : nullptr;

	if ( ! CheckErrorEventTypes(stream_name, error_event, true) )
		return false;

	vector<Field*> fieldsV; // vector, because we don't know the length beforehands

	bool status = (! UnrollRecordType(&fieldsV, idx, "", false));

	int idxfields = fieldsV.size();

	if ( val ) // if we are not a set
		status = status || ! UnrollRecordType(&fieldsV, val.get(), "",
		                                      BifConst::Input::accept_unsupported_types);

	int valfields = fieldsV.size() - idxfields;

	if ( (valfields > 1) && (want_record->InternalInt() != 1) )
		{
		reporter->Error("Input stream %s: Stream does not want a record (want_record=F), but has "
		                "more then one value field.",
		                stream_name.c_str());
		for ( auto& f : fieldsV )
			delete f;
		return false;
		}

	if ( ! val )
		assert(valfields == 0);

	if ( status )
		{
		reporter->Error("Input stream %s: Problem unrolling", stream_name.c_str());
		for ( auto& f : fieldsV )
			delete f;
		return false;
		}

	TableStream* stream = new TableStream();
		{
		bool res = CreateStream(stream, fval);
		if ( ! res )
			{
			delete stream;
			for ( auto& f : fieldsV )
				delete f;
			return false;
			}
		}

	Field** fields = new Field*[fieldsV.size()];
	for ( size_t i = 0; i < fieldsV.size(); i++ )
		fields[i] = fieldsV[i];

	stream->pred = pred ? pred->AsFunc() : nullptr;
	stream->num_idx_fields = idxfields;
	stream->num_val_fields = valfields;
	stream->tab = dst.release()->AsTableVal();
	stream->rtype = val.release();
	stream->itype = idx->Ref()->AsRecordType();
	stream->event = event ? event_registry->Lookup(event->Name()) : nullptr;
	stream->error_event = error_event ? event_registry->Lookup(error_event->Name()) : nullptr;
	stream->currDict = new PDict<InputHash>;
	stream->currDict->SetDeleteFunc(input_hash_delete_func);
	stream->lastDict = new PDict<InputHash>;
	stream->lastDict->SetDeleteFunc(input_hash_delete_func);
	stream->want_record = (want_record->InternalInt() == 1);

	assert(stream->reader);
	stream->reader->Init(fieldsV.size(), fields);

	readers[stream->reader] = stream;

	DBG_LOG(DBG_INPUT, "Successfully created table stream %s", stream->name.c_str());

	return true;
	}

bool Manager::CheckErrorEventTypes(const std::string& stream_name, const Func* ev, bool table) const
	{
	if ( ev == nullptr )
		return true;

	const auto& etype = ev->GetType();

	if ( etype->Flavor() != FUNC_FLAVOR_EVENT )
		{
		reporter->Error("Input stream %s: Error event is a function, not an event",
		                stream_name.c_str());
		return false;
		}

	const auto& args = etype->ParamList()->GetTypes();

	if ( args.size() != 3 )
		{
		reporter->Error("Input stream %s: Error event must take 3 arguments", stream_name.c_str());
		return false;
		}

	if ( table && ! same_type(args[0], BifType::Record::Input::TableDescription, false) )
		{
		reporter->Error("Input stream %s: Error event's first attribute must be of type "
		                "Input::TableDescription",
		                stream_name.c_str());
		return false;
		}

	if ( ! table && ! same_type(args[0], BifType::Record::Input::EventDescription, false) )
		{
		reporter->Error("Input stream %s: Error event's first attribute must be of type "
		                "Input::EventDescription",
		                stream_name.c_str());
		return false;
		}

	if ( args[1]->Tag() != TYPE_STRING )
		{
		reporter->Error("Input stream %s: Error event's second attribute must be of type string",
		                stream_name.c_str());
		return false;
		}

	if ( ! same_type(args[2], BifType::Enum::Reporter::Level, false) )
		{
		reporter->Error(
			"Input stream %s: Error event's third attribute must be of type Reporter::Level",
			stream_name.c_str());
		return false;
		}

	return true;
	}

bool Manager::CreateAnalysisStream(RecordVal* fval)
	{
	RecordType* rtype = fval->GetType()->AsRecordType();

	if ( ! same_type(rtype, BifType::Record::Input::AnalysisDescription, false) )
		{
		reporter->Error("AnalysisDescription argument not of right type");
		return false;
		}

	AnalysisStream* stream = new AnalysisStream();

	if ( ! CreateStream(stream, fval) )
		{
		delete stream;
		return false;
		}

	stream->file_id = file_mgr->HashHandle(stream->name);

	assert(stream->reader);

	// reader takes in a byte stream as the only field
	Field** fields = new Field*[1];
	fields[0] = new Field("bytestream", nullptr, TYPE_STRING, TYPE_VOID, false);
	stream->reader->Init(1, fields);

	readers[stream->reader] = stream;

	DBG_LOG(DBG_INPUT, "Successfully created analysis stream %s", stream->name.c_str());

	return true;
	}

bool Manager::IsCompatibleType(Type* t, bool atomic_only)
	{
	if ( ! t )
		return false;

	switch ( t->Tag() )
		{
		case TYPE_BOOL:
		case TYPE_INT:
		case TYPE_COUNT:
		case TYPE_PORT:
		case TYPE_SUBNET:
		case TYPE_ADDR:
		case TYPE_DOUBLE:
		case TYPE_TIME:
		case TYPE_INTERVAL:
		case TYPE_ENUM:
		case TYPE_STRING:
		case TYPE_PATTERN:
			return true;

		case TYPE_RECORD:
			return ! atomic_only;

		case TYPE_TABLE:
			{
			if ( atomic_only )
				return false;

			if ( ! t->IsSet() )
				return false;

			const auto& indices = t->AsSetType()->GetIndices();

			if ( indices->GetTypes().size() != 1 )
				return false;

			return IsCompatibleType(indices->GetPureType().get(), true);
			}

		case TYPE_VECTOR:
			{
			if ( atomic_only )
				return false;

			return IsCompatibleType(t->AsVectorType()->Yield().get(), true);
			}

		default:
			return false;
		}

	return false;
	}

bool Manager::RemoveStream(Stream* i)
	{
	if ( i == nullptr )
		return false; // not found

	if ( i->removed )
		{
		reporter->Warning("Stream %s is already queued for removal. Ignoring remove.",
		                  i->name.c_str());
		return true;
		}

	i->removed = true;

	DBG_LOG(DBG_INPUT, "Successfully queued removal of stream %s", i->name.c_str());

	i->reader->Stop();

	return true;
	}

bool Manager::RemoveStream(ReaderFrontend* frontend)
	{
	return RemoveStream(FindStream(frontend));
	}

bool Manager::RemoveStream(const string& name)
	{
	return RemoveStream(FindStream(name));
	}

bool Manager::RemoveStreamContinuation(ReaderFrontend* reader)
	{
	Stream* i = FindStream(reader);

	if ( i == nullptr )
		{
		reporter->Error("Stream not found in RemoveStreamContinuation");
		return false;
		}

#ifdef DEBUG
	DBG_LOG(DBG_INPUT, "Successfully executed removal of stream %s", i->name.c_str());
#endif

	readers.erase(reader);
	delete (i);

	return true;
	}

bool Manager::UnrollRecordType(vector<Field*>* fields, const RecordType* rec,
                               const string& nameprepend, bool allow_file_func) const
	{
	for ( int i = 0; i < rec->NumFields(); i++ )
		{
		if ( ! IsCompatibleType(rec->GetFieldType(i).get()) )
			{
			string name = nameprepend + rec->FieldName(i);
			// If the field is a file, function, or opaque
			// and it is optional, we accept it nevertheless.
			// This allows importing logfiles containing this
			// stuff that we actually cannot read :)
			if ( allow_file_func )
				{
				if ( (rec->GetFieldType(i)->Tag() == TYPE_FILE ||
				      rec->GetFieldType(i)->Tag() == TYPE_FUNC ||
				      rec->GetFieldType(i)->Tag() == TYPE_OPAQUE) &&
				     rec->FieldDecl(i)->GetAttr(detail::ATTR_OPTIONAL) )
					{
					reporter->Info("Encountered incompatible type \"%s\" in type definition for "
					               "field \"%s\" in ReaderFrontend. Ignoring optional field.",
					               type_name(rec->GetFieldType(i)->Tag()), name.c_str());
					continue;
					}
				}

			reporter->Error("Incompatible type \"%s\" in type definition for field \"%s\" in "
			                "ReaderFrontend",
			                type_name(rec->GetFieldType(i)->Tag()), name.c_str());
			return false;
			}

		if ( rec->GetFieldType(i)->Tag() == TYPE_RECORD )
			{
			string prep = nameprepend + rec->FieldName(i) + ".";

			if ( rec->FieldDecl(i)->GetAttr(zeek::detail::ATTR_OPTIONAL) )
				{
				reporter->Info(
					"The input framework does not support optional record fields: \"%s\"",
					rec->FieldName(i));
				return false;
				}

			if ( ! UnrollRecordType(fields, rec->GetFieldType(i)->AsRecordType(), prep,
			                        allow_file_func) )
				{
				return false;
				}
			}

		else
			{
			string name = nameprepend + rec->FieldName(i);
			const char* secondary = nullptr;
			ValPtr c;
			TypeTag ty = rec->GetFieldType(i)->Tag();
			TypeTag st = TYPE_VOID;
			bool optional = false;

			if ( ty == TYPE_TABLE )
				st = rec->GetFieldType(i)->AsSetType()->GetIndices()->GetPureType()->Tag();

			else if ( ty == TYPE_VECTOR )
				st = rec->GetFieldType(i)->AsVectorType()->Yield()->Tag();

			else if ( ty == TYPE_PORT &&
			          rec->FieldDecl(i)->GetAttr(zeek::detail::ATTR_TYPE_COLUMN) )
				{
				// we have an annotation for the second column

				c = rec->FieldDecl(i)
				        ->GetAttr(zeek::detail::ATTR_TYPE_COLUMN)
				        ->GetExpr()
				        ->Eval(nullptr);

				assert(c);
				assert(c->GetType()->Tag() == TYPE_STRING);

				secondary = c->AsStringVal()->AsString()->CheckString();
				}

			if ( rec->FieldDecl(i)->GetAttr(zeek::detail::ATTR_OPTIONAL) )
				optional = true;

			Field* field = new Field(name.c_str(), secondary, ty, st, optional);
			fields->push_back(field);
			}
		}

	return true;
	}

bool Manager::ForceUpdate(const string& name)
	{
	Stream* i = FindStream(name);
	if ( i == nullptr )
		{
		reporter->Error("Stream %s not found", name.c_str());
		return false;
		}

	if ( i->removed )
		{
		reporter->Error("Stream %s is already queued for removal. Ignoring force update.",
		                name.c_str());
		return false;
		}

	i->reader->Update();

#ifdef DEBUG
	DBG_LOG(DBG_INPUT, "Forcing update of stream %s", name.c_str());
#endif

	return true; // update is async :(
	}

Val* Manager::RecordValToIndexVal(RecordVal* r) const
	{
	ValPtr idxval;

	RecordType* type = r->GetType()->AsRecordType();

	int num_fields = type->NumFields();

	if ( num_fields == 1 && type->FieldDecl(0)->type->Tag() != TYPE_RECORD )
		idxval = r->GetFieldOrDefault(0);

	else
		{
		auto l = make_intrusive<ListVal>(TYPE_ANY);
		for ( int j = 0; j < num_fields; j++ )
			l->Append(r->GetFieldOrDefault(j));

		idxval = std::move(l);
		}

	return idxval.release();
	}

Val* Manager::ValueToIndexVal(const Stream* i, int num_fields, const RecordType* type,
                              const Value* const* vals, bool& have_error) const
	{
	Val* idxval;
	int position = 0;

	if ( num_fields == 1 && type->GetFieldType(0)->Tag() != TYPE_RECORD )
		{
		idxval = ValueToVal(i, vals[0], type->GetFieldType(0).get(), have_error);
		position = 1;
		}
	else
		{
		auto l = make_intrusive<ListVal>(TYPE_ANY);
		for ( int j = 0; j < type->NumFields(); j++ )
			{
			if ( type->GetFieldType(j)->Tag() == TYPE_RECORD )
				{
				auto rv = ValueToRecordVal(i, vals, type->GetFieldType(j)->AsRecordType(),
				                           &position, have_error);
				if ( have_error )
					break;

				l->Append({AdoptRef{}, rv});
				}
			else
				{
				// Bail early here if we already have an error. ValueToVal() won't do
				// anything in that case, and by checking first we know that if
				// ValueToVal() returns nullptr, there is a new problem.
				if ( have_error )
					break;

				auto v = ValueToVal(i, vals[position], type->GetFieldType(j).get(), have_error);
				if ( ! v )
					{
					// Since we're building a (list) value for indexing into
					// a table, it is for sure an error to miss a value.
					auto source = i->reader->Info().source;
					auto file_pos = vals[position]->GetFileLineNumber();

					const char* warning = "Skipping input with missing non-optional value";
					if ( source && file_pos != -1 )
						Warning(i, "%s:%d: %s", source, file_pos, warning);
					else
						Warning(i, "%s", warning);

					have_error = true;
					}

				if ( have_error )
					break;

				l->Append({AdoptRef{}, v});
				position++;
				}
			}

		if ( have_error )
			return nullptr;

		idxval = l.release();
		}

	assert(position == num_fields);

	return idxval;
	}

void Manager::SendEntry(ReaderFrontend* reader, Value** vals)
	{
	Stream* i = FindStream(reader);
	if ( i == nullptr )
		{
		reporter->InternalWarning("Unknown reader %s in SendEntry", reader->Name());
		return;
		}

	int readFields = 0;

	if ( i->stream_type == TABLE_STREAM )
		readFields = SendEntryTable(i, vals);

	else if ( i->stream_type == EVENT_STREAM )
		{
		auto type = BifType::Enum::Input::Event->GetEnumVal(BifEnum::Input::EVENT_NEW);
		readFields = SendEventStreamEvent(i, type.release(), vals);
		}

	else if ( i->stream_type == ANALYSIS_STREAM )
		{
		readFields = 1;
		assert(vals[0]->type == TYPE_STRING);
		file_mgr->DataIn(reinterpret_cast<u_char*>(vals[0]->val.string_val.data),
		                 vals[0]->val.string_val.length, static_cast<AnalysisStream*>(i)->file_id,
		                 i->name);
		}

	else
		assert(false);

	Value::delete_value_ptr_array(vals, readFields);
	}

int Manager::SendEntryTable(Stream* i, const Value* const* vals)
	{
	bool updated = false;

	assert(i);

	assert(i->stream_type == TABLE_STREAM);
	TableStream* stream = (TableStream*)i;

	zeek::detail::HashKey* idxhash = HashValues(stream->num_idx_fields, vals);

	if ( idxhash == nullptr )
		{
		Warning(i, "Could not hash line. Ignoring");
		return stream->num_val_fields + stream->num_idx_fields;
		}

	zeek::detail::hash_t valhash = 0;
	if ( stream->num_val_fields > 0 )
		{
		if ( zeek::detail::HashKey* valhashkey = HashValues(stream->num_val_fields,
		                                                    vals + stream->num_idx_fields) )
			{
			valhash = valhashkey->Hash();
			delete (valhashkey);
			}
		else
			{
			// empty line. index, but no values.
			// hence we also have no hash value...
			}
		}

	InputHash* h = stream->lastDict->Lookup(idxhash);
	if ( h )
		{
		// seen before
		if ( stream->num_val_fields == 0 || h->valhash == valhash )
			{
			// ok, exact duplicate, move entry to new dictionary and do nothing else.
			stream->lastDict->Remove(idxhash);
			stream->currDict->Insert(idxhash, h);
			delete idxhash;
			return stream->num_val_fields + stream->num_idx_fields;
			}

		else
			{
			assert(stream->num_val_fields > 0);
			// entry was updated in some way
			stream->lastDict->Remove(idxhash);
			// keep h for predicates
			updated = true;
			}
		}

	Val* valval;
	RecordVal* predidx = nullptr;

	int position = stream->num_idx_fields;

	bool convert_error = false; // this will be set to true by ValueTo* on Error

	if ( stream->num_val_fields == 0 )
		valval = nullptr;

	else if ( stream->num_val_fields == 1 && ! stream->want_record )
		valval = ValueToVal(i, vals[position], stream->rtype->GetFieldType(0).get(), convert_error);

	else
		valval = ValueToRecordVal(i, vals, stream->rtype, &position, convert_error);

	// call stream first to determine if we really add / change the entry
	if ( stream->pred && ! convert_error )
		{
		EnumValPtr ev;
		int startpos = 0;
		bool pred_convert_error = false;
		predidx = ValueToRecordVal(i, vals, stream->itype, &startpos, pred_convert_error);

		// if we encountered a convert error here - just continue as we would have without
		// emitting the event. I do not really think that can happen just here and not
		// at the top-level. But - this is safe.
		if ( ! pred_convert_error )
			{
			if ( updated )
				ev = BifType::Enum::Input::Event->GetEnumVal(BifEnum::Input::EVENT_CHANGED);
			else
				ev = BifType::Enum::Input::Event->GetEnumVal(BifEnum::Input::EVENT_NEW);

			bool result;
			if ( stream->num_val_fields > 0 ) // we have values
				result = CallPred(stream->pred, 3, ev.release(), predidx->Ref(), valval->Ref());
			else // no values
				result = CallPred(stream->pred, 2, ev.release(), predidx->Ref());

			if ( result == false )
				{
				Unref(predidx);
				Unref(valval);

				if ( ! updated )
					{
					// just quit and delete everything we created.
					delete idxhash;
					return stream->num_val_fields + stream->num_idx_fields;
					}

				else
					{
					// keep old one
					stream->currDict->Insert(idxhash, h);
					delete idxhash;
					return stream->num_val_fields + stream->num_idx_fields;
					}
				}
			}
		}

	// now we don't need h anymore - if we are here, the entry is updated and a new h is created.
	delete h;
	h = nullptr;

	Val* idxval;
	if ( predidx != nullptr )
		{
		idxval = RecordValToIndexVal(predidx);
		// I think there is an unref missing here. But if I insert is, it crashes :)
		}
	else
		idxval = ValueToIndexVal(i, stream->num_idx_fields, stream->itype, vals, convert_error);

	if ( convert_error )
		{
		// abort here and free everything that was allocated so far.
		Unref(predidx);
		Unref(valval);
		Unref(idxval);

		delete idxhash;
		return stream->num_val_fields + stream->num_idx_fields;
		}

	assert(idxval);

	ValPtr oldval;
	if ( updated == true )
		{
		assert(stream->num_val_fields > 0);
		// in that case, we need the old value to send the event (if we send an event).
		oldval = stream->tab->Find({NewRef{}, idxval});
		}

	auto k = stream->tab->MakeHashKey(*idxval);

	if ( ! k )
		reporter->InternalError("could not hash");

	InputHash* ih = new InputHash();
	ih->idxkey = new zeek::detail::HashKey(k->Key(), k->Size(), k->Hash());
	ih->valhash = valhash;

	stream->tab->Assign({AdoptRef{}, idxval}, std::move(k), {AdoptRef{}, valval});

	if ( predidx != nullptr )
		Unref(predidx);

	auto prev = stream->currDict->Insert(idxhash, ih);
	delete prev;
	delete idxhash;

	if ( stream->event )
		{
		int startpos = 0;
		Val* predidx = ValueToRecordVal(i, vals, stream->itype, &startpos, convert_error);

		if ( convert_error )
			{
			// the only thing to clean up here is predidx. Everything else should
			// already be ok again
			Unref(predidx);
			}
		else if ( updated )
			{ // in case of update send back the old value.
			assert(stream->num_val_fields > 0);
			auto ev = BifType::Enum::Input::Event->GetEnumVal(BifEnum::Input::EVENT_CHANGED);
			assert(oldval != nullptr);
			SendEvent(stream->event, 4, stream->description->Ref(), ev.release(), predidx,
			          oldval.release());
			}
		else
			{
			auto ev = BifType::Enum::Input::Event->GetEnumVal(BifEnum::Input::EVENT_NEW);
			if ( stream->num_val_fields == 0 )
				SendEvent(stream->event, 3, stream->description->Ref(), ev.release(), predidx);
			else
				SendEvent(stream->event, 4, stream->description->Ref(), ev.release(), predidx,
				          valval->Ref());
			}
		}

	return stream->num_val_fields + stream->num_idx_fields;
	}

void Manager::EndCurrentSend(ReaderFrontend* reader)
	{
	Stream* i = FindStream(reader);

	if ( i == nullptr )
		{
		reporter->InternalWarning("Unknown reader %s in EndCurrentSend", reader->Name());
		return;
		}

#ifdef DEBUG
	DBG_LOG(DBG_INPUT, "Got EndCurrentSend stream %s", i->name.c_str());
#endif

	if ( i->stream_type != TABLE_STREAM )
		{
#ifdef DEBUG
		DBG_LOG(DBG_INPUT, "%s is event, sending end of data", i->name.c_str());
#endif
		// just signal the end of the data source
		SendEndOfData(i);
		return;
		}

	assert(i->stream_type == TABLE_STREAM);
	auto* stream = static_cast<TableStream*>(i);

	// lastdict contains all deleted entries and should be empty apart from that
	for ( auto it = stream->lastDict->begin_robust(); it != stream->lastDict->end_robust(); ++it )
		{
		auto lastDictIdxKey = it->GetHashKey();
		InputHash* ih = it->value;

		ValPtr val;
		ValPtr predidx;
		EnumValPtr ev;
		int startpos = 0;

		if ( stream->pred || stream->event )
			{
			auto idx = stream->tab->RecreateIndex(*ih->idxkey);
			assert(idx != nullptr);
			val = stream->tab->FindOrDefault(idx);
			assert(val != nullptr);
			predidx = {AdoptRef{}, ListValToRecordVal(idx.get(), stream->itype, &startpos)};
			ev = BifType::Enum::Input::Event->GetEnumVal(BifEnum::Input::EVENT_REMOVED);
			}

		if ( stream->pred )
			{
			// ask predicate, if we want to expire this element...

			bool result = CallPred(stream->pred, 3, ev->Ref(), predidx->Ref(), val->Ref());

			if ( result == false )
				{
				// Keep it. Hence - we quit and simply go to the next entry of lastDict
				// ah well - and we have to add the entry to currDict...
				stream->currDict->Insert(lastDictIdxKey.get(),
				                         stream->lastDict->RemoveEntry(lastDictIdxKey.get()));
				continue;
				}
			}

		if ( stream->event )
			{
			if ( stream->num_val_fields == 0 )
				SendEvent(stream->event, 3, stream->description->Ref(), ev->Ref(), predidx->Ref());
			else
				SendEvent(stream->event, 4, stream->description->Ref(), ev->Ref(), predidx->Ref(),
				          val->Ref());
			}

		stream->tab->Remove(*ih->idxkey);
		stream->lastDict->Remove(lastDictIdxKey.get()); // delete in next line
		delete ih;
		}

	stream->lastDict->Clear(); // should be empty. but well... who knows...
	delete stream->lastDict;

	stream->lastDict = stream->currDict;
	stream->currDict = new PDict<InputHash>;
	stream->currDict->SetDeleteFunc(input_hash_delete_func);

#ifdef DEBUG
	DBG_LOG(DBG_INPUT, "EndCurrentSend complete for stream %s", i->name.c_str());
#endif

	SendEndOfData(i);
	}

void Manager::SendEndOfData(ReaderFrontend* reader)
	{
	Stream* i = FindStream(reader);

	if ( i == nullptr )
		{
		reporter->InternalWarning("Unknown reader %s in SendEndOfData", reader->Name());
		return;
		}

	SendEndOfData(i);
	}

void Manager::SendEndOfData(const Stream* i)
	{
#ifdef DEBUG
	DBG_LOG(DBG_INPUT, "SendEndOfData for stream %s", i->name.c_str());
#endif
	auto name = make_intrusive<StringVal>(i->name.c_str());
	auto source = make_intrusive<StringVal>(i->reader->Info().source);
	SendEvent(end_of_data, 2, name->Ref(), source->Ref());

	if ( i->stream_type == ANALYSIS_STREAM )
		file_mgr->EndOfFile(static_cast<const AnalysisStream*>(i)->file_id);
	}

void Manager::Put(ReaderFrontend* reader, Value** vals)
	{
	Stream* i = FindStream(reader);
	if ( i == nullptr )
		{
		reporter->InternalWarning("Unknown reader %s in Put", reader->Name());
		return;
		}

#ifdef DEBUG
	DBG_LOG(DBG_INPUT, "Put for stream %s", i->name.c_str());
#endif

	int readFields = 0;

	if ( i->stream_type == TABLE_STREAM )
		readFields = PutTable(i, vals);

	else if ( i->stream_type == EVENT_STREAM )
		{
		auto type = BifType::Enum::Input::Event->GetEnumVal(BifEnum::Input::EVENT_NEW);
		readFields = SendEventStreamEvent(i, type.release(), vals);
		}

	else if ( i->stream_type == ANALYSIS_STREAM )
		{
		readFields = 1;
		assert(vals[0]->type == TYPE_STRING);
		file_mgr->DataIn(reinterpret_cast<u_char*>(vals[0]->val.string_val.data),
		                 vals[0]->val.string_val.length, static_cast<AnalysisStream*>(i)->file_id,
		                 i->name);
		}

	else
		assert(false);

	Value::delete_value_ptr_array(vals, readFields);
	}

int Manager::SendEventStreamEvent(Stream* i, EnumVal* type, const Value* const* vals)
	{
	assert(i);

	assert(i->stream_type == EVENT_STREAM);
	EventStream* stream = (EventStream*)i;

	list<Val*> out_vals;
	Ref(stream->description);
	out_vals.push_back(stream->description);
	// no tracking, send everything with a new event...
	out_vals.push_back(type);

	int position = 0;

	bool convert_error = false;

	if ( stream->want_record )
		{
		RecordVal* r = ValueToRecordVal(i, vals, stream->fields, &position, convert_error);

		if ( ! convert_error )
			out_vals.push_back(r);
		}

	else
		{
		for ( int j = 0; j < stream->fields->NumFields(); j++ )
			{
			Val* val = nullptr;

			if ( stream->fields->GetFieldType(j)->Tag() == TYPE_RECORD )
				val = ValueToRecordVal(i, vals, stream->fields->GetFieldType(j)->AsRecordType(),
				                       &position, convert_error);

			else
				{
				val = ValueToVal(i, vals[position], stream->fields->GetFieldType(j).get(),
				                 convert_error);
				position++;
				}

			if ( convert_error )
				break;

			out_vals.push_back(val);
			}
		}

	if ( convert_error )
		{
		// we have an error somewhere in our out_vals. Just delete all of them.
		for ( list<Val*>::const_iterator it = out_vals.begin(), end = out_vals.end(); it != end;
		      ++it )
			Unref(*it);
		}
	else
		SendEvent(stream->event, out_vals);

	return stream->num_fields;
	}

int Manager::PutTable(Stream* i, const Value* const* vals)
	{
	assert(i);

	assert(i->stream_type == TABLE_STREAM);
	TableStream* stream = (TableStream*)i;

	bool convert_error = false;

	Val* idxval = ValueToIndexVal(i, stream->num_idx_fields, stream->itype, vals, convert_error);
	Val* valval;

	int position = stream->num_idx_fields;

	if ( stream->num_val_fields == 0 )
		valval = nullptr;

	else if ( stream->num_val_fields == 1 && stream->want_record == 0 )
		valval = ValueToVal(i, vals[position], stream->rtype->GetFieldType(0).get(), convert_error);
	else
		valval = ValueToRecordVal(i, vals, stream->rtype, &position, convert_error);

	if ( convert_error )
		{
		Unref(valval);
		Unref(idxval);
		return stream->num_idx_fields + stream->num_val_fields;
		}

	// if we have a subscribed event, we need to figure out, if this is an update or not
	// same for predicates
	if ( stream->pred || stream->event )
		{
		bool updated = false;
		ValPtr oldval;

		if ( stream->num_val_fields > 0 )
			{
			// in that case, we need the old value to send the event (if we send an event).
			oldval = stream->tab->Find({NewRef{}, idxval});
			}

		if ( oldval != nullptr )
			{
			// it is an update
			updated = true;
			}

		// predicate if we want the update or not
		if ( stream->pred )
			{
			EnumValPtr ev;
			int startpos = 0;
			bool pred_convert_error = false;
			Val* predidx = ValueToRecordVal(i, vals, stream->itype, &startpos, pred_convert_error);

			if ( pred_convert_error )
				Unref(predidx);
			else
				{
				if ( updated )
					ev = BifType::Enum::Input::Event->GetEnumVal(BifEnum::Input::EVENT_CHANGED);
				else
					ev = BifType::Enum::Input::Event->GetEnumVal(BifEnum::Input::EVENT_NEW);

				bool result;
				if ( stream->num_val_fields > 0 ) // we have values
					{
					Ref(valval);
					result = CallPred(stream->pred, 3, ev.release(), predidx, valval);
					}
				else // no values
					result = CallPred(stream->pred, 2, ev.release(), predidx);

				if ( result == false )
					{
					// do nothing
					Unref(idxval);
					Unref(valval);
					return stream->num_val_fields + stream->num_idx_fields;
					}
				}
			}

		stream->tab->Assign({NewRef{}, idxval}, {AdoptRef{}, valval});

		if ( stream->event )
			{
			int startpos = 0;
			bool event_convert_error = false;
			Val* predidx = ValueToRecordVal(i, vals, stream->itype, &startpos, event_convert_error);

			if ( event_convert_error )
				Unref(predidx);
			else
				{
				if ( updated )
					{
					// in case of update send back the old value.
					assert(stream->num_val_fields > 0);
					auto ev = BifType::Enum::Input::Event->GetEnumVal(
						BifEnum::Input::EVENT_CHANGED);
					assert(oldval != nullptr);
					SendEvent(stream->event, 4, stream->description->Ref(), ev.release(), predidx,
					          oldval.release());
					}
				else
					{
					auto ev = BifType::Enum::Input::Event->GetEnumVal(BifEnum::Input::EVENT_NEW);
					if ( stream->num_val_fields == 0 )
						SendEvent(stream->event, 3, stream->description->Ref(), ev.release(),
						          predidx);
					else
						SendEvent(stream->event, 4, stream->description->Ref(), ev.release(),
						          predidx, valval->Ref());
					}
				}
			}
		}

	else // no predicates or other stuff
		stream->tab->Assign({NewRef{}, idxval}, {AdoptRef{}, valval});

	Unref(idxval); // not consumed by assign

	return stream->num_idx_fields + stream->num_val_fields;
	}

// Todo:: perhaps throw some kind of clear-event?
void Manager::Clear(ReaderFrontend* reader)
	{
	Stream* i = FindStream(reader);
	if ( i == nullptr )
		{
		reporter->InternalWarning("Unknown reader %s in Clear", reader->Name());
		return;
		}

#ifdef DEBUG
	DBG_LOG(DBG_INPUT, "Got Clear for stream %s", i->name.c_str());
#endif

	assert(i->stream_type == TABLE_STREAM);
	TableStream* stream = (TableStream*)i;

	stream->tab->RemoveAll();
	}

// put interface: delete old entry from table.
bool Manager::Delete(ReaderFrontend* reader, Value** vals)
	{
	Stream* i = FindStream(reader);
	if ( i == nullptr )
		{
		reporter->InternalWarning("Unknown reader %s in Delete", reader->Name());
		return false;
		}

	bool success = false;
	int readVals = 0;

	if ( i->stream_type == TABLE_STREAM )
		{
		TableStream* stream = (TableStream*)i;
		bool convert_error = false;
		Val* idxval = ValueToIndexVal(i, stream->num_idx_fields, stream->itype, vals,
		                              convert_error);
		readVals = stream->num_idx_fields + stream->num_val_fields;
		bool streamresult = true;

		if ( convert_error )
			{
			Unref(idxval);
			return false;
			}

		assert(idxval != nullptr);

		if ( stream->pred || stream->event )
			{
			auto val = stream->tab->FindOrDefault({NewRef{}, idxval});

			if ( stream->pred )
				{
				int startpos = 0;
				Val* predidx = ValueToRecordVal(i, vals, stream->itype, &startpos, convert_error);

				if ( convert_error )
					Unref(predidx);
				else
					{
					auto ev = BifType::Enum::Input::Event->GetEnumVal(
						BifEnum::Input::EVENT_REMOVED);

					streamresult = CallPred(stream->pred, 3, ev.release(), predidx,
					                        IntrusivePtr{val}.release());

					if ( streamresult == false )
						{
						// keep it.
						Unref(idxval);
						success = true;
						}
					}
				}

			// only if stream = true -> no streaming
			if ( streamresult && stream->event )
				{
				Ref(idxval);
				assert(val != nullptr);
				auto ev = BifType::Enum::Input::Event->GetEnumVal(BifEnum::Input::EVENT_REMOVED);
				if ( stream->num_val_fields == 0 )
					SendEvent(stream->event, 3, stream->description->Ref(), ev.release(), idxval);
				else
					SendEvent(stream->event, 4, stream->description->Ref(), ev.release(), idxval,
					          IntrusivePtr{val}.release());
				}
			}

		// only if stream = true -> no streaming
		if ( streamresult )
			{
			if ( ! stream->tab->Remove(*idxval) )
				Warning(i, "Internal error while deleting values from input table");
			}
		}

	else if ( i->stream_type == EVENT_STREAM )
		{
		auto type = BifType::Enum::Input::Event->GetEnumVal(BifEnum::Input::EVENT_REMOVED);
		readVals = SendEventStreamEvent(i, type.release(), vals);
		success = true;
		}

	else if ( i->stream_type == ANALYSIS_STREAM )
		{
		// can't do anything
		success = true;
		}

	else
		{
		assert(false);
		return false;
		}

	Value::delete_value_ptr_array(vals, readVals);
	return success;
	}

bool Manager::CallPred(Func* pred_func, const int numvals, ...) const
	{
	bool result = false;
	zeek::Args vl;
	vl.reserve(numvals);

	va_list lP;
	va_start(lP, numvals);
	for ( int i = 0; i < numvals; i++ )
		vl.emplace_back(AdoptRef{}, va_arg(lP, Val*));

	va_end(lP);

	auto v = pred_func->Invoke(&vl);

	if ( v )
		result = v->AsBool();

	return result;
	}

void Manager::SendEvent(EventHandlerPtr ev, const int numvals, ...) const
	{
	zeek::Args vl;
	vl.reserve(numvals);

#ifdef DEBUG
	DBG_LOG(DBG_INPUT, "SendEvent with %d vals", numvals);
#endif

	va_list lP;
	va_start(lP, numvals);
	for ( int i = 0; i < numvals; i++ )
		vl.emplace_back(AdoptRef{}, va_arg(lP, Val*));

	va_end(lP);

	if ( ev )
		event_mgr.Enqueue(ev, std::move(vl), util::detail::SOURCE_LOCAL);
	}

void Manager::SendEvent(EventHandlerPtr ev, list<Val*> events) const
	{
	zeek::Args vl;
	vl.reserve(events.size());

#ifdef DEBUG
	DBG_LOG(DBG_INPUT, "SendEvent with %" PRIuPTR " vals (list)", events.size());
#endif

	for ( list<Val*>::iterator i = events.begin(); i != events.end(); i++ )
		vl.emplace_back(AdoptRef{}, *i);

	if ( ev )
		event_mgr.Enqueue(ev, std::move(vl), util::detail::SOURCE_LOCAL);
	}

// Convert a Zeek list value to a Zeek record value.
// I / we could think about moving this functionality to val.cc
RecordVal* Manager::ListValToRecordVal(ListVal* list, RecordType* request_type, int* position) const
	{
	assert(position != nullptr); // we need the pointer to point to data;

	auto* rec = new RecordVal({NewRef{}, request_type});

	assert(list != nullptr);
	int maxpos = list->Length();

	for ( int i = 0; i < request_type->NumFields(); i++ )
		{
		assert((*position) <= maxpos);

		Val* fieldVal = nullptr;
		if ( request_type->GetFieldType(i)->Tag() == TYPE_RECORD )
			fieldVal = ListValToRecordVal(list, request_type->GetFieldType(i)->AsRecordType(),
			                              position);
		else
			{
			fieldVal = list->Idx(*position).get();
			(*position)++;
			}

		rec->Assign(i, {NewRef{}, fieldVal});
		}

	return rec;
	}

// Convert a threading value to a record value
RecordVal* Manager::ValueToRecordVal(const Stream* stream, const Value* const* vals,
                                     RecordType* request_type, int* position,
                                     bool& have_error) const
	{
	assert(position != nullptr); // we need the pointer to point to data.

	auto rec = make_intrusive<RecordVal>(RecordTypePtr{NewRef{}, request_type});
	for ( int i = 0; i < request_type->NumFields(); i++ )
		{
		Val* fieldVal = nullptr;
		if ( request_type->GetFieldType(i)->Tag() == TYPE_RECORD )
			fieldVal = ValueToRecordVal(stream, vals, request_type->GetFieldType(i)->AsRecordType(),
			                            position, have_error);
		else if ( request_type->GetFieldType(i)->Tag() == TYPE_FILE ||
		          request_type->GetFieldType(i)->Tag() == TYPE_FUNC )
			{
			// If those two unsupported types are encountered here, they have
			// been let through by the type checking.
			// That means that they are optional & the user agreed to ignore
			// them and has been warned by reporter.
			// Hence -> assign null to the field, done.

			// Better check that it really is optional. Uou never know.
			assert(request_type->FieldDecl(i)->GetAttr(zeek::detail::ATTR_OPTIONAL));
			}
		else if ( ! vals[*position]->present &&
		          ! request_type->FieldDecl(i)->GetAttr(zeek::detail::ATTR_OPTIONAL) )
			{
			auto source = stream->reader->Info().source;
			auto file_pos = vals[*position]->GetFileLineNumber();

			const char* warning = "Skipping input with missing non-optional value";
			if ( source && file_pos != -1 )
				Warning(stream, "%s:%d: %s", source, file_pos, warning);
			else
				Warning(stream, "%s", warning);

			have_error = true;
			}
		else
			{
			fieldVal = ValueToVal(stream, vals[*position], request_type->GetFieldType(i).get(),
			                      have_error);
			(*position)++;
			}

		if ( have_error )
			return nullptr;
		else if ( fieldVal )
			rec->Assign(i, {AdoptRef{}, fieldVal});
		}

	return rec.release();
	}

// Count the length of the values used to create a correct length buffer for
// hashing later
int Manager::GetValueLength(const Value* val) const
	{
	assert(val->present); // presence has to be checked elsewhere
	int length = 0;

	switch ( val->type )
		{
		case TYPE_BOOL:
		case TYPE_INT:
			length += sizeof(val->val.int_val);
			break;

		case TYPE_COUNT:
			length += sizeof(val->val.uint_val);
			break;

		case TYPE_PORT:
			length += sizeof(val->val.port_val.port);
			length += sizeof(val->val.port_val.proto);
			break;

		case TYPE_DOUBLE:
		case TYPE_TIME:
		case TYPE_INTERVAL:
			length += sizeof(val->val.double_val);
			break;

		case TYPE_STRING:
		case TYPE_ENUM:
			{
			length += val->val.string_val.length + 1;
			break;
			}

		case TYPE_ADDR:
			{
			switch ( val->val.addr_val.family )
				{
				case IPv4:
					length += sizeof(val->val.addr_val.in.in4);
					break;
				case IPv6:
					length += sizeof(val->val.addr_val.in.in6);
					break;
				default:
					assert(false);
				}
			}
			break;

		case TYPE_SUBNET:
			{
			switch ( val->val.subnet_val.prefix.family )
				{
				case IPv4:
					length += sizeof(val->val.subnet_val.prefix.in.in4) +
					          sizeof(val->val.subnet_val.length);
					break;
				case IPv6:
					length += sizeof(val->val.subnet_val.prefix.in.in6) +
					          sizeof(val->val.subnet_val.length);
					break;
				default:
					assert(false);
				}
			}
			break;

		case TYPE_PATTERN:
			{
			length += strlen(val->val.pattern_text_val) + 1;
			break;
			}

		case TYPE_TABLE:
			{
			for ( int i = 0; i < val->val.set_val.size; i++ )
				length += GetValueLength(val->val.set_val.vals[i]);
			break;
			}

		case TYPE_VECTOR:
			{
			int j = val->val.vector_val.size;
			for ( int i = 0; i < j; i++ )
				length += GetValueLength(val->val.vector_val.vals[i]);
			break;
			}

		default:
			reporter->InternalError("unsupported type %d for GetValueLength", val->type);
		}

	return length;
	}

// Given a threading::value, copy the raw data bytes into *data and return how many bytes were
// copied. Used for hashing the values for lookup in the Zeek table
int Manager::CopyValue(char* data, const int startpos, const Value* val) const
	{
	assert(val->present); // presence has to be checked elsewhere

	switch ( val->type )
		{
		case TYPE_BOOL:
		case TYPE_INT:
			memcpy(data + startpos, (const void*)&(val->val.int_val), sizeof(val->val.int_val));
			return sizeof(val->val.int_val);

		case TYPE_COUNT:
			memcpy(data + startpos, (const void*)&(val->val.uint_val), sizeof(val->val.uint_val));
			return sizeof(val->val.uint_val);

		case TYPE_PORT:
			{
			int length = 0;
			memcpy(data + startpos, (const void*)&(val->val.port_val.port),
			       sizeof(val->val.port_val.port));
			length += sizeof(val->val.port_val.port);
			memcpy(data + startpos + length, (const void*)&(val->val.port_val.proto),
			       sizeof(val->val.port_val.proto));
			length += sizeof(val->val.port_val.proto);
			return length;
			}

		case TYPE_DOUBLE:
		case TYPE_TIME:
		case TYPE_INTERVAL:
			memcpy(data + startpos, (const void*)&(val->val.double_val),
			       sizeof(val->val.double_val));
			return sizeof(val->val.double_val);

		case TYPE_STRING:
		case TYPE_ENUM:
			{
			memcpy(data + startpos, val->val.string_val.data, val->val.string_val.length);
			// Add a \0 to the end. To be able to hash zero-length
			// strings and differentiate from !present.
			memset(data + startpos + val->val.string_val.length, 0, 1);
			return val->val.string_val.length + 1;
			}

		case TYPE_ADDR:
			{
			int length = 0;
			switch ( val->val.addr_val.family )
				{
				case IPv4:
					length = sizeof(val->val.addr_val.in.in4);
					memcpy(data + startpos, (const char*)&(val->val.addr_val.in.in4), length);
					break;

				case IPv6:
					length = sizeof(val->val.addr_val.in.in6);
					memcpy(data + startpos, (const char*)&(val->val.addr_val.in.in6), length);
					break;

				default:
					assert(false);
				}

			return length;
			}

		case TYPE_SUBNET:
			{
			int length = 0;
			switch ( val->val.subnet_val.prefix.family )
				{
				case IPv4:
					length = sizeof(val->val.addr_val.in.in4);
					memcpy(data + startpos, (const char*)&(val->val.subnet_val.prefix.in.in4),
					       length);
					break;

				case IPv6:
					length = sizeof(val->val.addr_val.in.in6);
					memcpy(data + startpos, (const char*)&(val->val.subnet_val.prefix.in.in6),
					       length);
					break;

				default:
					assert(false);
				}

			int lengthlength = sizeof(val->val.subnet_val.length);
			memcpy(data + startpos + length, (const char*)&(val->val.subnet_val.length),
			       lengthlength);
			length += lengthlength;

			return length;
			}

		case TYPE_PATTERN:
			{
			// include null-terminator
			int length = strlen(val->val.pattern_text_val) + 1;
			memcpy(data + startpos, val->val.pattern_text_val, length);
			return length;
			}

		case TYPE_TABLE:
			{
			int length = 0;
			int j = val->val.set_val.size;
			for ( int i = 0; i < j; i++ )
				length += CopyValue(data, startpos + length, val->val.set_val.vals[i]);

			return length;
			}

		case TYPE_VECTOR:
			{
			int length = 0;
			int j = val->val.vector_val.size;
			for ( int i = 0; i < j; i++ )
				length += CopyValue(data, startpos + length, val->val.vector_val.vals[i]);

			return length;
			}

		default:
			reporter->InternalError("unsupported type %d for CopyValue", val->type);
			return 0;
		}

	assert(false);
	return 0;
	}

// Hash num_elements threading values and return the HashKey for them. At least one of the vals has
// to be ->present.
zeek::detail::HashKey* Manager::HashValues(const int num_elements, const Value* const* vals) const
	{
	int length = 0;

	for ( int i = 0; i < num_elements; i++ )
		{
		const Value* val = vals[i];
		if ( val->present )
			length += GetValueLength(val);

		// And in any case add 1 for the end-of-field-identifier.
		length++;
		}

	assert(length >= num_elements);

	if ( length == num_elements )
		return nullptr;

	int position = 0;
	char* data = new char[length];

	for ( int i = 0; i < num_elements; i++ )
		{
		const Value* val = vals[i];
		if ( val->present )
			position += CopyValue(data, position, val);

		memset(data + position, 1, 1); // Add end-of-field-marker. Does not really matter which
		                               // value it is, it just has to be... something.

		position++;
		}

	auto key = new zeek::detail::HashKey(data, length);
	delete[] data;

	assert(position == length);
	return key;
	}

// convert threading value to Zeek value
// have_error is a reference to a boolean which is set to true as soon as an error occurs.
// When have_error is set to true at the beginning of the function, it is assumed that
// an error already occurred in the past and processing is aborted.
Val* Manager::ValueToVal(const Stream* i, const Value* val, Type* request_type,
                         bool& have_error) const
	{
	if ( have_error )
		return nullptr;

	if ( request_type->Tag() != TYPE_ANY && request_type->Tag() != val->type )
		{
		reporter->InternalError("Typetags don't match: %d vs %d in stream %s", request_type->Tag(),
		                        val->type, i->name.c_str());
		return nullptr;
		}

	if ( ! val->present )
		return nullptr; // unset field

	switch ( val->type )
		{
		case TYPE_BOOL:
			return val_mgr->Bool(val->val.int_val)->Ref();

		case TYPE_INT:
			return val_mgr->Int(val->val.int_val).release();

		case TYPE_COUNT:
			return val_mgr->Count(val->val.int_val).release();

		case TYPE_DOUBLE:
			return new DoubleVal(val->val.double_val);

		case TYPE_TIME:
			return new TimeVal(val->val.double_val);

		case TYPE_INTERVAL:
			return new IntervalVal(val->val.double_val);

		case TYPE_STRING:
			{
			String* s = new String((const u_char*)val->val.string_val.data,
			                       val->val.string_val.length, true);
			return new StringVal(s);
			}

		case TYPE_PORT:
			return val_mgr->Port(val->val.port_val.port, val->val.port_val.proto)->Ref();

		case TYPE_ADDR:
			{
			IPAddr* addr = nullptr;
			switch ( val->val.addr_val.family )
				{
				case IPv4:
					addr = new IPAddr(val->val.addr_val.in.in4);
					break;

				case IPv6:
					addr = new IPAddr(val->val.addr_val.in.in6);
					break;

				default:
					assert(false);
				}

			auto* addrval = new AddrVal(*addr);
			delete addr;
			return addrval;
			}

		case TYPE_SUBNET:
			{
			IPAddr* addr = nullptr;
			switch ( val->val.subnet_val.prefix.family )
				{
				case IPv4:
					addr = new IPAddr(val->val.subnet_val.prefix.in.in4);
					break;

				case IPv6:
					addr = new IPAddr(val->val.subnet_val.prefix.in.in6);
					break;

				default:
					assert(false);
				}

			auto* subnetval = new SubNetVal(*addr, val->val.subnet_val.length);
			delete addr;
			return subnetval;
			}

		case TYPE_PATTERN:
			{
			auto* re = new RE_Matcher(val->val.pattern_text_val);
			re->Compile();
			return new PatternVal(re);
			}

		case TYPE_TABLE:
			{
			// all entries have to have the same type...
			const auto& type = request_type->AsTableType()->GetIndices()->GetPureType();
			auto set_index = make_intrusive<TypeList>(type);
			set_index->Append(type);
			auto s = make_intrusive<SetType>(std::move(set_index), nullptr);
			auto t = make_intrusive<TableVal>(std::move(s));
			for ( int j = 0; j < val->val.set_val.size; j++ )
				{
				Val* assignval = ValueToVal(i, val->val.set_val.vals[j], type.get(), have_error);

				if ( have_error )
					return nullptr;

				t->Assign({AdoptRef{}, assignval}, nullptr);
				}

			return t.release();
			}

		case TYPE_VECTOR:
			{
			// all entries have to have the same type...
			const auto& type = request_type->AsVectorType()->Yield();
			auto vt = make_intrusive<VectorType>(type);
			auto v = make_intrusive<VectorVal>(std::move(vt));

			for ( int j = 0; j < val->val.vector_val.size; j++ )
				{
				auto el = ValueToVal(i, val->val.vector_val.vals[j], type.get(), have_error);

				if ( have_error )
					return nullptr;

				v->Assign(j, {AdoptRef{}, el});
				}

			return v.release();
			}

		case TYPE_ENUM:
			{
			// Convert to string first to not have to deal with missing
			// \0's...
			string enum_string(val->val.string_val.data, val->val.string_val.length);

			string module = zeek::detail::extract_module_name(enum_string.c_str());
			string var = zeek::detail::extract_var_name(enum_string.c_str());

			// Well, this is kind of stupid, because EnumType just
			// mangles the module name and the var name together again...
			// but well.
			zeek_int_t index = request_type->AsEnumType()->Lookup(module, var.c_str());
			if ( index == -1 )
				{
				Warning(i, "Value '%s' for stream '%s' is not a valid enum.", enum_string.c_str(),
				        i->name.c_str());

				have_error = true;
				return nullptr;
				}

			auto rval = request_type->AsEnumType()->GetEnumVal(index);
			return rval.release();
			}

		default:
			reporter->InternalError("Unsupported type for input_read in stream %s",
			                        i->name.c_str());
		}

	assert(false);
	return nullptr;
	}

Manager::Stream* Manager::FindStream(const string& name) const
	{
	for ( auto s = readers.begin(); s != readers.end(); ++s )
		{
		if ( (*s).second->name == name )
			return (*s).second;
		}

	return nullptr;
	}

Manager::Stream* Manager::FindStream(ReaderFrontend* reader) const
	{
	auto s = readers.find(reader);
	if ( s != readers.end() )
		return s->second;

	return nullptr;
	}

// Function is called on Zeek shutdown.
// Signal all frontends that they will cease operation.
void Manager::Terminate()
	{
	for ( map<ReaderFrontend*, Stream*>::iterator i = readers.begin(); i != readers.end(); ++i )
		{
		if ( i->second->removed )
			continue;

		i->second->removed = true;
		i->second->reader->Stop();
		}
	}

void Manager::Info(ReaderFrontend* reader, const char* msg) const
	{
	Stream* i = FindStream(reader);
	if ( ! i )
		{
		reporter->Error("Stream not found in Info; lost message: %s", msg);
		return;
		}

	ErrorHandler(i, ErrorType::INFO, false, "%s", msg);
	}

void Manager::Warning(ReaderFrontend* reader, const char* msg) const
	{
	Stream* i = FindStream(reader);
	if ( ! i )
		{
		reporter->Error("Stream not found in Warning; lost message: %s", msg);
		return;
		}

	ErrorHandler(i, ErrorType::WARNING, false, "%s", msg);
	}

void Manager::Error(ReaderFrontend* reader, const char* msg) const
	{
	Stream* i = FindStream(reader);
	if ( ! i )
		{
		reporter->Error("Stream not found in Error; lost message: %s", msg);
		return;
		}

	ErrorHandler(i, ErrorType::ERROR, false, "%s", msg);
	}

void Manager::Info(const Stream* i, const char* fmt, ...) const
	{
	va_list ap;
	va_start(ap, fmt);
	ErrorHandler(i, ErrorType::INFO, true, fmt, ap);
	va_end(ap);
	}

void Manager::Warning(const Stream* i, const char* fmt, ...) const
	{
	va_list ap;
	va_start(ap, fmt);
	ErrorHandler(i, ErrorType::WARNING, true, fmt, ap);
	va_end(ap);
	}

void Manager::Error(const Stream* i, const char* fmt, ...) const
	{
	va_list ap;
	va_start(ap, fmt);
	ErrorHandler(i, ErrorType::ERROR, true, fmt, ap);
	va_end(ap);
	}

void Manager::ErrorHandler(const Stream* i, ErrorType et, bool reporter_send, const char* fmt,
                           ...) const
	{
	va_list ap;
	va_start(ap, fmt);
	ErrorHandler(i, et, reporter_send, fmt, ap);
	va_end(ap);
	}

void Manager::ErrorHandler(const Stream* i, ErrorType et, bool reporter_send, const char* fmt,
                           va_list ap) const
	{
	char* buf;

	int n = vasprintf(&buf, fmt, ap);
	if ( n < 0 || buf == nullptr )
		{
		reporter->InternalError("Could not format error message %s for stream %s", fmt,
		                        i->name.c_str());
		return;
		}

	// send our script level error event
	if ( i->error_event )
		{
		EnumValPtr ev;
		switch ( et )
			{
			case ErrorType::INFO:
				ev = BifType::Enum::Reporter::Level->GetEnumVal(BifEnum::Reporter::INFO);
				break;

			case ErrorType::WARNING:
				ev = BifType::Enum::Reporter::Level->GetEnumVal(BifEnum::Reporter::WARNING);
				break;

			case ErrorType::ERROR:
				ev = BifType::Enum::Reporter::Level->GetEnumVal(BifEnum::Reporter::ERROR);
				break;

			default:
				reporter->InternalError("Unknown error type while trying to report input error %s",
				                        fmt);
				__builtin_unreachable();
			}

		auto message = make_intrusive<StringVal>(buf);
		SendEvent(i->error_event, 3, i->description->Ref(), message->Ref(), ev.release());
		}

	if ( reporter_send )
		{
		switch ( et )
			{
			case ErrorType::INFO:
				reporter->Info("%s", buf);
				break;

			case ErrorType::WARNING:
				reporter->Warning("%s", buf);
				break;

			case ErrorType::ERROR:
				reporter->Error("%s", buf);
				break;

			default:
				reporter->InternalError("Unknown error type while trying to report input error %s",
				                        fmt);
			}
		}

	free(buf);
	}

	} // namespace zeek::input
