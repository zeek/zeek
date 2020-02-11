// See the file "COPYING" in the main distribution directory for copyright.

#include "Manager.h"

#include <string>
#include <utility>

#include "ReaderFrontend.h"
#include "ReaderBackend.h"
#include "Desc.h"
#include "module_util.h"
#include "input.bif.h"

#include "Expr.h"
#include "Event.h"
#include "EventHandler.h"
#include "NetVar.h"
#include "Net.h"
#include "CompHash.h"

#include "../file_analysis/Manager.h"
#include "../threading/SerialTypes.h"

using namespace input;
using threading::Value;
using threading::Field;

static void delete_value_ptr_array(Value** vals, int num_fields)
	{
	for ( int i = 0; i < num_fields; ++i )
		delete vals[i];

	delete [] vals;
	}

/**
 * InputHashes are used as Dictionaries to store the value and index hashes
 * for all lines currently stored in a table. Index hash is stored as
 * HashKey*, because it is thrown into other Bro functions that need the
 * complex structure of it. For everything we do (with values), we just take
 * the hash_t value and compare it directly with "=="
 */
struct InputHash {
	hash_t valhash;
	HashKey* idxkey;
	~InputHash();
};

InputHash::~InputHash()
	{
	delete idxkey;
	}

static void input_hash_delete_func(void* val)
	{
	InputHash* h = (InputHash*) val;
	delete h;
	}

/**
 * Base stuff that every stream can do.
 */
class Manager::Stream {
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
    : name(), removed(), stream_type(t), type(), reader(), config(),
      error_event(), description()
	{
	}

Manager::Stream::~Stream()
	{
	if ( type )
	        Unref(type);

	if ( description )
	        Unref(description);

	if ( config )
		Unref(config);

	if ( reader )
	        delete(reader);
	}

class Manager::TableStream: public Manager::Stream {
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
	~TableStream();
};

class Manager::EventStream: public Manager::Stream {
public:
	EventHandlerPtr event;

	RecordType* fields;
	unsigned int num_fields;

	bool want_record;
	EventStream();
	~EventStream();
};

class Manager::AnalysisStream: public Manager::Stream {
public:
	string file_id;

	AnalysisStream();
	~AnalysisStream();
};

Manager::TableStream::TableStream()
	: Manager::Stream::Stream(TABLE_STREAM),
	  num_idx_fields(), num_val_fields(), want_record(), tab(), rtype(),
	  itype(), currDict(), lastDict(), pred(), event()
	{
	}

Manager::EventStream::EventStream()
	: Manager::Stream::Stream(EVENT_STREAM),
	  event(), fields(), num_fields(), want_record()
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

	if ( currDict != 0 )
		{
		currDict->Clear();
		delete currDict;
		}

	if ( lastDict != 0 )
		{
		lastDict->Clear();;
		delete lastDict;
		}
	}

Manager::AnalysisStream::AnalysisStream()
	: Manager::Stream::Stream(ANALYSIS_STREAM), file_id()
	{
	}

Manager::AnalysisStream::~AnalysisStream()
	{
	}

Manager::Manager()
	: plugin::ComponentManager<input::Tag, input::Component>("Input", "Reader")
	{
	end_of_data = internal_handler("Input::end_of_data");
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
		reporter->Error("The reader that was requested was not found and could not be initialized.");
		return 0;
		}

	ReaderBackend* backend = (*c->Factory())(frontend);
	assert(backend);

	return backend;
	}

// Create a new input reader object to be used at whomevers leisure later on.
bool Manager::CreateStream(Stream* info, RecordVal* description)
	{
	RecordType* rtype = description->Type()->AsRecordType();
	if ( ! ( same_type(rtype, BifType::Record::Input::TableDescription, 0)
		|| same_type(rtype, BifType::Record::Input::EventDescription, 0)
		|| same_type(rtype, BifType::Record::Input::AnalysisDescription, 0) ) )
		{
		reporter->Error("Stream description argument not of right type for new input stream");
		return false;
		}

	Val* name_val = description->Lookup("name", true);
	string name = name_val->AsString()->CheckString();
	Unref(name_val);

	Stream *i = FindStream(name);
	if ( i != 0 )
		{
		reporter->Error("Trying create already existing input stream %s",
				name.c_str());
		return false;
		}

	EnumVal* reader = description->Lookup("reader", true)->AsEnumVal();

	// get the source ...
	Val* sourceval = description->Lookup("source", true);
	assert ( sourceval != 0 );
	const BroString* bsource = sourceval->AsString();
	string source((const char*) bsource->Bytes(), bsource->Len());
	Unref(sourceval);

	ReaderBackend::ReaderInfo rinfo;
	rinfo.source = copy_string(source.c_str());
	rinfo.name = copy_string(name.c_str());

	EnumVal* mode = description->Lookup("mode", true)->AsEnumVal();
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
			Unref(mode);
			return false;
		}

	Unref(mode);

	Val* config = description->Lookup("config", true);
	info->config = config->AsTableVal(); // ref'd by LookupWithDefault

		{
		// create config mapping in ReaderInfo. Has to be done before the construction of reader_obj.
		HashKey* k;
		IterCookie* c = info->config->AsTable()->InitForIteration();

		TableEntryVal* v;
		while ( (v = info->config->AsTable()->NextEntry(k, c)) )
			{
			ListVal* index = info->config->RecoverIndex(k);
			string key = index->Index(0)->AsString()->CheckString();
			string value = v->Value()->AsString()->CheckString();
			rinfo.config.insert(std::make_pair(copy_string(key.c_str()), copy_string(value.c_str())));
			Unref(index);
			delete k;
			}

		}


	ReaderFrontend* reader_obj = new ReaderFrontend(rinfo, reader);
	assert(reader_obj);

	info->reader = reader_obj;
	info->type = reader->AsEnumVal(); // ref'd by lookupwithdefault
	info->name = name;

	Ref(description);
	info->description = description;


	DBG_LOG(DBG_INPUT, "Successfully created new input stream %s",
		name.c_str());

	return true;
	}

bool Manager::CreateEventStream(RecordVal* fval)
	{
	RecordType* rtype = fval->Type()->AsRecordType();
	if ( ! same_type(rtype, BifType::Record::Input::EventDescription, 0) )
		{
		reporter->Error("EventDescription argument not of right type");
		return false;
		}

	Val* name_val = fval->Lookup("name", true);
	string stream_name = name_val->AsString()->CheckString();
	Unref(name_val);

	Val* fields_val = fval->Lookup("fields", true);
	RecordType *fields = fields_val->AsType()->AsTypeType()->Type()->AsRecordType();
	Unref(fields_val);

	Val *want_record = fval->Lookup("want_record", true);

	Val* event_val = fval->Lookup("ev", true);
	Func* event = event_val->AsFunc();
	Unref(event_val);

	FuncType* etype = event->FType()->AsFuncType();

	bool allow_file_func = false;

	if ( etype->Flavor() != FUNC_FLAVOR_EVENT )
		{
		reporter->Error("Input stream %s: Stream event is a function, not an event", stream_name.c_str());
		return false;
		}

	const type_list* args = etype->ArgTypes()->Types();

	if ( args->length() < 2 )
		{
		reporter->Error("Input stream %s: Event does not take enough arguments", stream_name.c_str());
		return false;
		}

	if ( ! same_type((*args)[1], BifType::Enum::Input::Event, 0) )
		{
		reporter->Error("Input stream %s: Event's second attribute must be of type Input::Event", stream_name.c_str());
		return false;
		}

	if ( ! same_type((*args)[0], BifType::Record::Input::EventDescription, 0) )
		{
		reporter->Error("Input stream %s: Event's first attribute must be of type Input::EventDescription", stream_name.c_str());
		return false;
		}

	if ( want_record->InternalInt() == 0 )
		{
		if ( args->length() != fields->NumFields() + 2 )
			{
			reporter->Error("Input stream %s: Event has wrong number of arguments", stream_name.c_str());
			return false;
			}

		for ( int i = 0; i < fields->NumFields(); i++ )
			{
			if ( ! same_type((*args)[i + 2], fields->FieldType(i) ) )
				{
				ODesc desc1;
				ODesc desc2;
				(*args)[i + 2]->Describe(&desc1);
				fields->FieldType(i)->Describe(&desc2);

				reporter->Error("Input stream %s: Incompatible type for event in field %d. Need type '%s':%s, got '%s':%s",
						stream_name.c_str(), i + 3,
						type_name(fields->FieldType(i)->Tag()), desc2.Description(),
						type_name((*args)[i + 2]->Tag()), desc1.Description());

				return false;
				}
			}

		}

	else if ( want_record->InternalInt() == 1 )
		{
		if ( args->length() != 3 )
			{
			reporter->Error("Input stream %s: Event has wrong number of arguments", stream_name.c_str());
			return false;
			}

		if ( ! same_type((*args)[2], fields ) )
			{
			ODesc desc1;
			ODesc desc2;
			(*args)[2]->Describe(&desc1);
			fields->Describe(&desc2);
			reporter->Error("Input stream %s: Incompatible type '%s':%s for event, which needs type '%s':%s\n",
					stream_name.c_str(),
					type_name((*args)[2]->Tag()), desc1.Description(),
					type_name(fields->Tag()), desc2.Description());
			return false;
			}

		allow_file_func = BifConst::Input::accept_unsupported_types;

		}

	else
		assert(false);

	Val* error_event_val = fval->Lookup("error_ev", true);
	Func* error_event = error_event_val ? error_event_val->AsFunc() : nullptr;
	Unref(error_event_val);

	if ( ! CheckErrorEventTypes(stream_name, error_event, false) )
		return false;

	vector<Field*> fieldsV; // vector, because UnrollRecordType needs it

	bool status = (! UnrollRecordType(&fieldsV, fields, "", allow_file_func));

	if ( status )
		{
		reporter->Error("Input stream %s: Problem unrolling", stream_name.c_str());
		for ( auto& f : fieldsV ) delete f;
		return false;
		}

	EventStream* stream = new EventStream();

	bool res = CreateStream(stream, fval);
	if ( ! res )
		{
		delete stream;
		for ( auto& f : fieldsV ) delete f;
		return false;
		}

	Field** logf = new Field*[fieldsV.size()];
	for ( unsigned int i = 0; i < fieldsV.size(); i++ )
		logf[i] = fieldsV[i];

	Unref(fields); // ref'd by lookupwithdefault
	stream->num_fields = fieldsV.size();
	stream->fields = fields->Ref()->AsRecordType();
	stream->event = event_registry->Lookup(event->Name());
	stream->error_event = error_event ? event_registry->Lookup(error_event->Name()) : nullptr;
	stream->want_record = ( want_record->InternalInt() == 1 );
	Unref(want_record); // ref'd by lookupwithdefault

	assert(stream->reader);

	stream->reader->Init(stream->num_fields, logf );

	readers[stream->reader] = stream;

	DBG_LOG(DBG_INPUT, "Successfully created event stream %s",
		stream->name.c_str());

	return true;
}

bool Manager::CreateTableStream(RecordVal* fval)
	{
	RecordType* rtype = fval->Type()->AsRecordType();
	if ( ! same_type(rtype, BifType::Record::Input::TableDescription, 0) )
		{
		reporter->Error("TableDescription argument not of right type");
		return false;
		}

	Val* name_val = fval->Lookup("name", true);
	string stream_name = name_val->AsString()->CheckString();
	Unref(name_val);

	Val* pred = fval->Lookup("pred", true);

	Val* idx_val = fval->Lookup("idx", true);
	RecordType *idx = idx_val->AsType()->AsTypeType()->Type()->AsRecordType();
	Unref(idx_val);

	RecordType *val = 0;

	Val* val_val = fval->Lookup("val", true);
	if ( val_val )
		{
		val = val_val->AsType()->AsTypeType()->Type()->AsRecordType();
		Unref(val_val);
		}

	TableVal *dst = fval->Lookup("destination", true)->AsTableVal();

	// check if index fields match table description
	int num = idx->NumFields();
	const type_list* tl = dst->Type()->AsTableType()->IndexTypes();

	loop_over_list(*tl, j)
		{
		if ( j >= num )
			{
			reporter->Error("Input stream %s: Table type has more indexes than index definition", stream_name.c_str());
			return false;
			}

		if ( ! same_type(idx->FieldType(j), (*tl)[j]) )
			{
			ODesc desc1;
			ODesc desc2;
			idx->FieldType(j)->Describe(&desc1);
			(*tl)[j]->Describe(&desc2);

			reporter->Error("Input stream %s: Table type does not match index type. Need type '%s':%s, got '%s':%s", stream_name.c_str(),
					type_name(idx->FieldType(j)->Tag()), desc1.Description(),
					type_name((*tl)[j]->Tag()), desc2.Description());

			return false;
			}
		}

	if ( num != j )
		{
		reporter->Error("Input stream %s: Table has less elements than index definition", stream_name.c_str());
		return false;
		}

	Val *want_record = fval->Lookup("want_record", true);

	if ( val )
		{
		const BroType* table_yield = dst->Type()->AsTableType()->YieldType();
		const BroType* compare_type = val;

		if ( want_record->InternalInt() == 0 )
			compare_type = val->FieldType(0);

		if ( ! same_type(table_yield, compare_type) )
			{
			ODesc desc1;
			ODesc desc2;
			compare_type->Describe(&desc1);
			table_yield->Describe(&desc2);
			reporter->Error("Input stream %s: Table type does not match value type. Need type '%s', got '%s'", stream_name.c_str(),
					desc1.Description(), desc2.Description());
			return false;
			}
		}
	else
		{
		if ( ! dst->Type()->IsSet() )
			{
			reporter->Error("Input stream %s: 'destination' field is a table,"
			                " but 'val' field is not provided"
			                " (did you mean to use a set instead of a table?)",
			                stream_name.c_str());
			return false;
			}
		}

	Val* event_val = fval->Lookup("ev", true);
	Func* event = event_val ? event_val->AsFunc() : 0;
	Unref(event_val);

	if ( event )
		{
		FuncType* etype = event->FType()->AsFuncType();

		if ( etype->Flavor() != FUNC_FLAVOR_EVENT )
			{
			reporter->Error("Input stream %s: Stream event is a function, not an event", stream_name.c_str());
			return false;
			}

		const type_list* args = etype->ArgTypes()->Types();

		if ( args->length() != 4 )
			{
			reporter->Error("Input stream %s: Table event must take 4 arguments", stream_name.c_str());
			return false;
			}

		if ( ! same_type((*args)[0], BifType::Record::Input::TableDescription, 0) )
			{
			reporter->Error("Input stream %s: Table event's first attribute must be of type Input::TableDescription", stream_name.c_str());
			return false;
			}

		if ( ! same_type((*args)[1], BifType::Enum::Input::Event, 0) )
			{
			reporter->Error("Input stream %s: Table event's second attribute must be of type Input::Event", stream_name.c_str());
			return false;
			}

		if ( ! same_type((*args)[2], idx) )
			{
			ODesc desc1;
			ODesc desc2;
			idx->Describe(&desc1);
			(*args)[2]->Describe(&desc2);
			reporter->Error("Input stream %s: Table event's index attributes do not match. Need '%s', got '%s'", stream_name.c_str(),
					desc1.Description(), desc2.Description());
			return false;
			}

		if ( want_record->InternalInt() == 1 && val && ! same_type((*args)[3], val) )
			{
			ODesc desc1;
			ODesc desc2;
			val->Describe(&desc1);
			(*args)[3]->Describe(&desc2);
			reporter->Error("Input stream %s: Table event's value attributes do not match. Need '%s', got '%s'", stream_name.c_str(),
					desc1.Description(), desc2.Description());
			return false;
			}
		else if (  want_record->InternalInt() == 0
		           && val && !same_type((*args)[3], val->FieldType(0) ) )
			{
			ODesc desc1;
			ODesc desc2;
			val->FieldType(0)->Describe(&desc1);
			(*args)[3]->Describe(&desc2);
			reporter->Error("Input stream %s: Table event's value attribute does not match. Need '%s', got '%s'", stream_name.c_str(),
					desc1.Description(), desc2.Description());
			return false;
			}
		else if ( ! val )
			{
			reporter->Error("Encountered a null value when creating a table stream");
			}

		assert(want_record->InternalInt() == 1 || want_record->InternalInt() == 0);
		}

	Val* error_event_val = fval->Lookup("error_ev", true);
	Func* error_event = error_event_val ? error_event_val->AsFunc() : nullptr;
	Unref(error_event_val);

	if ( ! CheckErrorEventTypes(stream_name, error_event, true) )
		return false;

	vector<Field*> fieldsV; // vector, because we don't know the length beforehands

	bool status = (! UnrollRecordType(&fieldsV, idx, "", false));

	int idxfields = fieldsV.size();

	if ( val ) // if we are not a set
		status = status || ! UnrollRecordType(&fieldsV, val, "", BifConst::Input::accept_unsupported_types);

	int valfields = fieldsV.size() - idxfields;

	if ( (valfields > 1) && (want_record->InternalInt() != 1) )
		{
		reporter->Error("Input stream %s: Stream does not want a record (want_record=F), but has more then one value field.", stream_name.c_str());
		for ( auto& f : fieldsV ) delete f;
		return false;
		}

	if ( ! val )
		assert(valfields == 0);

	if ( status )
		{
		reporter->Error("Input stream %s: Problem unrolling", stream_name.c_str());
		for ( auto& f : fieldsV ) delete f;
		return false;
		}

	TableStream* stream = new TableStream();
		{
		bool res = CreateStream(stream, fval);
		if ( ! res )
			{
			delete stream;
			for ( auto& f : fieldsV ) delete f;
			return false;
			}
		}

	Field** fields = new Field*[fieldsV.size()];
	for ( unsigned int i = 0; i < fieldsV.size(); i++ )
		fields[i] = fieldsV[i];

	stream->pred = pred ? pred->AsFunc() : 0;
	stream->num_idx_fields = idxfields;
	stream->num_val_fields = valfields;
	stream->tab = dst->AsTableVal(); // ref'd by lookupwithdefault
	stream->rtype = val ? val->AsRecordType() : 0;
	stream->itype = idx->AsRecordType();
	stream->event = event ? event_registry->Lookup(event->Name()) : 0;
	stream->error_event = error_event ? event_registry->Lookup(error_event->Name()) : nullptr;
	stream->currDict = new PDict<InputHash>;
	stream->currDict->SetDeleteFunc(input_hash_delete_func);
	stream->lastDict = new PDict<InputHash>;
	stream->lastDict->SetDeleteFunc(input_hash_delete_func);
	stream->want_record = ( want_record->InternalInt() == 1 );

	Unref(want_record); // ref'd by lookupwithdefault
	Unref(pred);

	assert(stream->reader);
	stream->reader->Init(fieldsV.size(), fields );

	readers[stream->reader] = stream;

	DBG_LOG(DBG_INPUT, "Successfully created table stream %s",
		stream->name.c_str());

	return true;
	}

bool Manager::CheckErrorEventTypes(const std::string& stream_name, const Func* ev, bool table) const
	{
	if ( ev == nullptr )
		return true;

	FuncType* etype = ev->FType()->AsFuncType();

	if ( etype->Flavor() != FUNC_FLAVOR_EVENT )
		{
		reporter->Error("Input stream %s: Error event is a function, not an event", stream_name.c_str());
		return false;
		}

	const type_list* args = etype->ArgTypes()->Types();

	if ( args->length() != 3 )
		{
		reporter->Error("Input stream %s: Error event must take 3 arguments", stream_name.c_str());
		return false;
		}

	if ( table && ! same_type((*args)[0], BifType::Record::Input::TableDescription, 0) )
		{
		reporter->Error("Input stream %s: Error event's first attribute must be of type Input::TableDescription", stream_name.c_str());
		return false;
		}

	if ( ! table && ! same_type((*args)[0], BifType::Record::Input::EventDescription, 0) )
		{
		reporter->Error("Input stream %s: Error event's first attribute must be of type Input::EventDescription", stream_name.c_str());
		return false;
		}

	if ( (*args)[1]->Tag() != TYPE_STRING )
		{
		reporter->Error("Input stream %s: Error event's second attribute must be of type string", stream_name.c_str());
		return false;
		}

	if ( ! same_type((*args)[2], BifType::Enum::Reporter::Level, 0) )
		{
		reporter->Error("Input stream %s: Error event's third attribute must be of type Reporter::Level", stream_name.c_str());
		return false;
		}

	return true;
	}

bool Manager::CreateAnalysisStream(RecordVal* fval)
	{
	RecordType* rtype = fval->Type()->AsRecordType();

	if ( ! same_type(rtype, BifType::Record::Input::AnalysisDescription, 0) )
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
	fields[0] = new Field("bytestream", 0, TYPE_STRING, TYPE_VOID, false);
	stream->reader->Init(1, fields);

	readers[stream->reader] = stream;

	DBG_LOG(DBG_INPUT, "Successfully created analysis stream %s",
		stream->name.c_str());

	return true;
	}

bool Manager::IsCompatibleType(BroType* t, bool atomic_only)
	{
	if ( ! t )
		return false;

	switch ( t->Tag() ) {
	case TYPE_BOOL:
	case TYPE_INT:
	case TYPE_COUNT:
	case TYPE_COUNTER:
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

		return IsCompatibleType(t->AsSetType()->Indices()->PureType(), true);
		}

	case TYPE_VECTOR:
		{
		if ( atomic_only )
			return false;

		return IsCompatibleType(t->AsVectorType()->YieldType(), true);
		}

	default:
		return false;
	}

	return false;
	}


bool Manager::RemoveStream(Stream *i)
	{
	if ( i == 0 )
		return false; // not found

	if ( i->removed )
		{
		reporter->Warning("Stream %s is already queued for removal. Ignoring remove.", i->name.c_str());
		return true;
		}

	i->removed = true;

	DBG_LOG(DBG_INPUT, "Successfully queued removal of stream %s",
		i->name.c_str());

	i->reader->Stop();

	return true;
	}

bool Manager::RemoveStream(ReaderFrontend* frontend)
	{
	return RemoveStream(FindStream(frontend));
	}


bool Manager::RemoveStream(const string &name)
	{
	return RemoveStream(FindStream(name));
	}


bool Manager::RemoveStreamContinuation(ReaderFrontend* reader)
	{
	Stream *i = FindStream(reader);

	if ( i == 0 )
		{
		reporter->Error("Stream not found in RemoveStreamContinuation");
		return false;
		}

#ifdef DEBUG
		DBG_LOG(DBG_INPUT, "Successfully executed removal of stream %s",
		i->name.c_str());
#endif

	readers.erase(reader);
	delete(i);

	return true;
	}

bool Manager::UnrollRecordType(vector<Field*> *fields, const RecordType *rec,
			       const string& nameprepend, bool allow_file_func) const
	{
	for ( int i = 0; i < rec->NumFields(); i++ )
		{

		if ( ! IsCompatibleType(rec->FieldType(i)) )
			{
			string name = nameprepend + rec->FieldName(i);
			// If the field is a file, function, or opaque
			// and it is optional, we accept it nevertheless.
			// This allows importing logfiles containing this
			// stuff that we actually cannot read :)
			if ( allow_file_func )
				{
				if ( ( rec->FieldType(i)->Tag() == TYPE_FILE ||
				       rec->FieldType(i)->Tag() == TYPE_FUNC ||
				       rec->FieldType(i)->Tag() == TYPE_OPAQUE ) &&
				       rec->FieldDecl(i)->FindAttr(ATTR_OPTIONAL) )
					{
					reporter->Info("Encountered incompatible type \"%s\" in type definition for field \"%s\" in ReaderFrontend. Ignoring optional field.", type_name(rec->FieldType(i)->Tag()), name.c_str());
					continue;
					}
				}

			reporter->Error("Incompatible type \"%s\" in type definition for for field \"%s\" in ReaderFrontend", type_name(rec->FieldType(i)->Tag()), name.c_str());
			return false;
			}

		if ( rec->FieldType(i)->Tag() == TYPE_RECORD )
			{
			string prep = nameprepend + rec->FieldName(i) + ".";

			if ( rec->FieldDecl(i)->FindAttr(ATTR_OPTIONAL) )
				{
				reporter->Info("The input framework does not support optional record fields: \"%s\"", rec->FieldName(i));
				return false;
				}

			if ( !UnrollRecordType(fields, rec->FieldType(i)->AsRecordType(), prep, allow_file_func) )
				{
				return false;
				}

			}

		else
			{
			string name = nameprepend + rec->FieldName(i);
			const char* secondary = 0;
			TypeTag ty = rec->FieldType(i)->Tag();
			TypeTag st = TYPE_VOID;
			bool optional = false;

			if ( ty == TYPE_TABLE )
				st = rec->FieldType(i)->AsSetType()->Indices()->PureType()->Tag();

			else if ( ty == TYPE_VECTOR )
				st = rec->FieldType(i)->AsVectorType()->YieldType()->Tag();

			else if ( ty == TYPE_PORT &&
				  rec->FieldDecl(i)->FindAttr(ATTR_TYPE_COLUMN) )
				{
				// we have an annotation for the second column

				Val* c = rec->FieldDecl(i)->FindAttr(ATTR_TYPE_COLUMN)->AttrExpr()->Eval(0);

				assert(c);
				assert(c->Type()->Tag() == TYPE_STRING);

				secondary = c->AsStringVal()->AsString()->CheckString();
				}

			if ( rec->FieldDecl(i)->FindAttr(ATTR_OPTIONAL ) )
				optional = true;

			Field* field = new Field(name.c_str(), secondary, ty, st, optional);
			fields->push_back(field);
			}
		}

	return true;
	}

bool Manager::ForceUpdate(const string &name)
	{
	Stream *i = FindStream(name);
	if ( i == 0 )
		{
		reporter->Error("Stream %s not found", name.c_str());
		return false;
		}

	if ( i->removed )
		{
		reporter->Error("Stream %s is already queued for removal. Ignoring force update.", name.c_str());
		return false;
		}

	i->reader->Update();

#ifdef DEBUG
	DBG_LOG(DBG_INPUT, "Forcing update of stream %s", name.c_str());
#endif

	return true; // update is async :(
}


Val* Manager::RecordValToIndexVal(RecordVal *r) const
	{
	Val* idxval;

	RecordType *type = r->Type()->AsRecordType();

	int num_fields = type->NumFields();

	if ( num_fields == 1 && type->FieldDecl(0)->type->Tag() != TYPE_RECORD  )
		idxval = r->LookupWithDefault(0);

	else
		{
		ListVal *l = new ListVal(TYPE_ANY);
		for ( int j = 0 ; j < num_fields; j++ )
			l->Append(r->LookupWithDefault(j));

		idxval = l;
		}


	return idxval;
	}


Val* Manager::ValueToIndexVal(const Stream* i, int num_fields, const RecordType *type, const Value* const *vals, bool& have_error) const
	{
	Val* idxval;
	int position = 0;


	if ( num_fields == 1 && type->FieldType(0)->Tag() != TYPE_RECORD  )
		{
		idxval = ValueToVal(i, vals[0], type->FieldType(0), have_error);
		position = 1;
		}
	else
		{
		ListVal *l = new ListVal(TYPE_ANY);
		for ( int j = 0 ; j < type->NumFields(); j++ )
			{
			if ( type->FieldType(j)->Tag() == TYPE_RECORD )
				l->Append(ValueToRecordVal(i, vals,
				          type->FieldType(j)->AsRecordType(), &position, have_error));
			else
				{
				l->Append(ValueToVal(i, vals[position], type->FieldType(j), have_error));
				position++;
				}
			}
		idxval = l;
		}

	assert ( position == num_fields );

	return idxval;
	}


void Manager::SendEntry(ReaderFrontend* reader, Value* *vals)
	{
	Stream *i = FindStream(reader);
	if ( i == 0 )
		{
		reporter->InternalWarning("Unknown reader %s in SendEntry",
		                          reader->Name());
		return;
		}

	int readFields = 0;

	if ( i->stream_type == TABLE_STREAM )
		readFields = SendEntryTable(i, vals);

	else if ( i->stream_type == EVENT_STREAM )
		{
		EnumVal *type = BifType::Enum::Input::Event->GetVal(BifEnum::Input::EVENT_NEW);
		readFields = SendEventStreamEvent(i, type, vals);
		}

	else if ( i->stream_type == ANALYSIS_STREAM )
		{
		readFields = 1;
		assert(vals[0]->type == TYPE_STRING);
		file_mgr->DataIn(reinterpret_cast<u_char*>(vals[0]->val.string_val.data),
		                 vals[0]->val.string_val.length,
		                 static_cast<AnalysisStream*>(i)->file_id, i->name);
		}

	else
		assert(false);

	delete_value_ptr_array(vals, readFields);
	}

int Manager::SendEntryTable(Stream* i, const Value* const *vals)
	{
	bool updated = false;

	assert(i);

	assert(i->stream_type == TABLE_STREAM);
	TableStream* stream = (TableStream*) i;

	HashKey* idxhash = HashValues(stream->num_idx_fields, vals);

	if ( idxhash == 0 )
		{
		Warning(i, "Could not hash line. Ignoring");
		return stream->num_val_fields + stream->num_idx_fields;
		}

	hash_t valhash = 0;
	if ( stream->num_val_fields > 0 )
		{
		HashKey* valhashkey = HashValues(stream->num_val_fields, vals+stream->num_idx_fields);
		if ( valhashkey == 0 )
			{
			// empty line. index, but no values.
			// hence we also have no hash value...
			}
		else
			{
			valhash = valhashkey->Hash();
			delete(valhashkey);
			}
		}

	InputHash *h = stream->lastDict->Lookup(idxhash);
	if ( h != 0 )
		{
		// seen before
		if ( stream->num_val_fields == 0 || h->valhash == valhash )
			{
			// ok, exact duplicate, move entry to new dicrionary and do nothing else.
			stream->lastDict->Remove(idxhash);
			stream->currDict->Insert(idxhash, h);
			delete idxhash;
			return stream->num_val_fields + stream->num_idx_fields;
			}

		else
			{
			assert( stream->num_val_fields > 0 );
			// entry was updated in some way
			stream->lastDict->Remove(idxhash);
			// keep h for predicates
			updated = true;
			}

		}

	Val* valval;
	RecordVal* predidx = 0;

	int position = stream->num_idx_fields;

	bool convert_error = false; // this will be set to true by ValueTo* on Error

	if ( stream->num_val_fields == 0 )
		valval = 0;

	else if ( stream->num_val_fields == 1 && !stream->want_record )
		valval = ValueToVal(i, vals[position], stream->rtype->FieldType(0), convert_error);

	else
		valval = ValueToRecordVal(i, vals, stream->rtype, &position, convert_error);

	// call stream first to determine if we really add / change the entry
	if ( stream->pred && ! convert_error )
		{
		EnumVal* ev;
		int startpos = 0;
		bool pred_convert_error = false;
		predidx = ValueToRecordVal(i, vals, stream->itype, &startpos, pred_convert_error);

		// if we encountered a convert error here - just continue as we would have without
		// emitting the event. I do not really think that that can happen just here and not
		// at the top-level. But - this is safe.
		if ( ! pred_convert_error )
			{
			if ( updated )
				ev = BifType::Enum::Input::Event->GetVal(BifEnum::Input::EVENT_CHANGED);
			else
				ev = BifType::Enum::Input::Event->GetVal(BifEnum::Input::EVENT_NEW);

			bool result;
			if ( stream->num_val_fields > 0 ) // we have values
				result = CallPred(stream->pred, 3, ev, predidx->Ref(), valval->Ref());
			else // no values
				result = CallPred(stream->pred, 2, ev, predidx->Ref());

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
	h = 0;

	Val* idxval;
	if ( predidx != 0 )
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

	Val* oldval = 0;
	if ( updated == true )
		{
		assert(stream->num_val_fields > 0);
		// in that case, we need the old value to send the event (if we send an event).
		oldval = stream->tab->Lookup(idxval, false);
		}

	HashKey* k = stream->tab->ComputeHash(idxval);
	if ( ! k )
		reporter->InternalError("could not hash");

	InputHash* ih = new InputHash();
	ih->idxkey = new HashKey(k->Key(), k->Size(), k->Hash());
	ih->valhash = valhash;

	if ( oldval && stream->event && updated )
		Ref(oldval); // otherwise it is no longer accessible after the assignment

	stream->tab->Assign(idxval, k, valval);
	Unref(idxval); // asssign does not consume idxval.

	if ( predidx != 0 )
		Unref(predidx);

	auto prev = stream->currDict->Insert(idxhash, ih);
	delete prev;
	delete idxhash;

	if ( stream->event )
		{
		EnumVal* ev;
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
			assert ( stream->num_val_fields > 0 );
			ev = BifType::Enum::Input::Event->GetVal(BifEnum::Input::EVENT_CHANGED);
			assert ( oldval != 0 );
			SendEvent(stream->event, 4, stream->description->Ref(), ev, predidx, oldval);
			}
		else
			{
			ev = BifType::Enum::Input::Event->GetVal(BifEnum::Input::EVENT_NEW);
			if ( stream->num_val_fields == 0 )
				{
				Ref(stream->description);
				SendEvent(stream->event, 3, stream->description->Ref(), ev, predidx);
				}
			else
				SendEvent(stream->event, 4, stream->description->Ref(), ev, predidx, valval->Ref());
			}
		}

	return stream->num_val_fields + stream->num_idx_fields;
	}

void Manager::EndCurrentSend(ReaderFrontend* reader)
	{
	Stream *i = FindStream(reader);

	if ( i == 0 )
		{
		reporter->InternalWarning("Unknown reader %s in EndCurrentSend",
		                          reader->Name());
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
	TableStream* stream = (TableStream*) i;

	// lastdict contains all deleted entries and should be empty apart from that
	IterCookie *c = stream->lastDict->InitForIteration();
	stream->lastDict->MakeRobustCookie(c);
	InputHash* ih;
	HashKey *lastDictIdxKey;

	while ( ( ih = stream->lastDict->NextEntry(lastDictIdxKey, c) ) )
		{
		ListVal * idx = 0;
		Val *val = 0;

		Val* predidx = 0;
		EnumVal* ev = 0;
		int startpos = 0;

		if ( stream->pred || stream->event )
			{
			idx = stream->tab->RecoverIndex(ih->idxkey);
			assert(idx != 0);
			val = stream->tab->Lookup(idx);
			assert(val != 0);
			predidx = ListValToRecordVal(idx, stream->itype, &startpos);
			Unref(idx);
			ev = BifType::Enum::Input::Event->GetVal(BifEnum::Input::EVENT_REMOVED);
			}

		if ( stream->pred )
			{
			// ask predicate, if we want to expire this element...

			Ref(ev);
			Ref(predidx);
			Ref(val);

			bool result = CallPred(stream->pred, 3, ev, predidx, val);

			if ( result == false )
				{
				// Keep it. Hence - we quit and simply go to the next entry of lastDict
				// ah well - and we have to add the entry to currDict...
				Unref(predidx);
				Unref(ev);
				stream->currDict->Insert(lastDictIdxKey, stream->lastDict->RemoveEntry(lastDictIdxKey));
				delete lastDictIdxKey;
				continue;
				}
			}

		if ( stream->event )
			{
			Ref(predidx);
			Ref(val);
			Ref(ev);
			SendEvent(stream->event, 4, stream->description->Ref(), ev, predidx, val);
			}

		if ( predidx )  // if we have a stream or an event...
			Unref(predidx);

		if ( ev )
			Unref(ev);

		Unref(stream->tab->Delete(ih->idxkey));
		stream->lastDict->Remove(lastDictIdxKey); // delete in next line
		delete lastDictIdxKey;
		delete(ih);
		}

	stream->lastDict->Clear(); // should be empt. buti- well... who knows...
	delete(stream->lastDict);

	stream->lastDict = stream->currDict;
	stream->currDict = new PDict<InputHash>;
	stream->currDict->SetDeleteFunc(input_hash_delete_func);

#ifdef DEBUG
	DBG_LOG(DBG_INPUT, "EndCurrentSend complete for stream %s",
		i->name.c_str());
#endif

	SendEndOfData(i);
	}

void Manager::SendEndOfData(ReaderFrontend* reader)
	{
	Stream *i = FindStream(reader);

	if ( i == 0 )
		{
		reporter->InternalWarning("Unknown reader %s in SendEndOfData",
		                          reader->Name());
		return;
		}

	SendEndOfData(i);
	}


void Manager::SendEndOfData(const Stream *i)
	{
#ifdef DEBUG
	DBG_LOG(DBG_INPUT, "SendEndOfData for stream %s",
		i->name.c_str());
#endif
	SendEvent(end_of_data, 2, new StringVal(i->name.c_str()),
	          new StringVal(i->reader->Info().source));

	if ( i->stream_type == ANALYSIS_STREAM )
		file_mgr->EndOfFile(static_cast<const AnalysisStream*>(i)->file_id);
	}

void Manager::Put(ReaderFrontend* reader, Value* *vals)
	{
	Stream *i = FindStream(reader);
	if ( i == 0 )
		{
		reporter->InternalWarning("Unknown reader %s in Put", reader->Name());
		return;
		}

#ifdef DEBUG
	DBG_LOG(DBG_INPUT, "Put for stream %s",
		i->name.c_str());
#endif

	int readFields = 0;

	if ( i->stream_type == TABLE_STREAM )
		readFields = PutTable(i, vals);

	else if ( i->stream_type == EVENT_STREAM )
		{
		EnumVal *type = BifType::Enum::Input::Event->GetVal(BifEnum::Input::EVENT_NEW);
		readFields = SendEventStreamEvent(i, type, vals);
		}

	else if ( i->stream_type == ANALYSIS_STREAM )
		{
		readFields = 1;
		assert(vals[0]->type == TYPE_STRING);
		file_mgr->DataIn(reinterpret_cast<u_char*>(vals[0]->val.string_val.data),
		                 vals[0]->val.string_val.length,
		                 static_cast<AnalysisStream*>(i)->file_id, i->name);
		}

	else
		assert(false);

	delete_value_ptr_array(vals, readFields);
	}

int Manager::SendEventStreamEvent(Stream* i, EnumVal* type, const Value* const *vals)
	{
	assert(i);

	assert(i->stream_type == EVENT_STREAM);
	EventStream* stream = (EventStream*) i;

	list<Val*> out_vals;
	Ref(stream->description);
	out_vals.push_back(stream->description);
	// no tracking, send everything with a new event...
	out_vals.push_back(type);

	int position = 0;

	bool convert_error = false;

	if ( stream->want_record )
		{
		RecordVal * r = ValueToRecordVal(i, vals, stream->fields, &position, convert_error);
		out_vals.push_back(r);
		}

	else
		{
		for ( int j = 0; j < stream->fields->NumFields(); j++)
			{
			Val* val = 0;

			if ( stream->fields->FieldType(j)->Tag() == TYPE_RECORD )
				val = ValueToRecordVal(i, vals,
						stream->fields->FieldType(j)->AsRecordType(),
						&position, convert_error);

			else
				{
				val = ValueToVal(i, vals[position], stream->fields->FieldType(j), convert_error);
				position++;
				}

			out_vals.push_back(val);
			}
		}

	if ( convert_error )
		{
		// we have an error somewhere in our out_vals. Just delete all of them.
		for ( list<Val*>::const_iterator it = out_vals.begin(), end = out_vals.end(); it != end; ++it )
			Unref(*it);
		}
	else
		SendEvent(stream->event, out_vals);

	return stream->num_fields;
	}

int Manager::PutTable(Stream* i, const Value* const *vals)
	{
	assert(i);

	assert(i->stream_type == TABLE_STREAM);
	TableStream* stream = (TableStream*) i;

	bool convert_error = 0;

	Val* idxval = ValueToIndexVal(i, stream->num_idx_fields, stream->itype, vals, convert_error);
	Val* valval;

	int position = stream->num_idx_fields;

	if ( stream->num_val_fields == 0 )
		valval = 0;

	else if ( stream->num_val_fields == 1 && stream->want_record == 0 )
		valval = ValueToVal(i, vals[position], stream->rtype->FieldType(0), convert_error);
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
		Val* oldval = 0;

		if ( stream->num_val_fields > 0 )
			{
			// in that case, we need the old value to send the event (if we send an event).
			oldval = stream->tab->Lookup(idxval, false);
			}

		if ( oldval != 0 )
			{
			// it is an update
			updated = true;
			Ref(oldval); // have to do that, otherwise it may disappear in assign
			}


		// predicate if we want the update or not
		if ( stream->pred )
			{
			EnumVal* ev;
			int startpos = 0;
			bool pred_convert_error = false;
			Val* predidx = ValueToRecordVal(i, vals, stream->itype, &startpos, pred_convert_error);

			if ( pred_convert_error )
				Unref(predidx);
			else
				{
				if ( updated )
					ev = BifType::Enum::Input::Event->GetVal(BifEnum::Input::EVENT_CHANGED);
				else
					ev = BifType::Enum::Input::Event->GetVal(BifEnum::Input::EVENT_NEW);

				bool result;
				if ( stream->num_val_fields > 0 ) // we have values
					{
					Ref(valval);
					result = CallPred(stream->pred, 3, ev, predidx, valval);
					}
				else // no values
					result = CallPred(stream->pred, 2, ev, predidx);

				if ( result == false )
					{
					// do nothing
					Unref(idxval);
					Unref(valval);
					Unref(oldval);
					return stream->num_val_fields + stream->num_idx_fields;
					}
				}

			}

		stream->tab->Assign(idxval, valval);

		if ( stream->event )
			{
			EnumVal* ev;
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
					assert ( stream->num_val_fields > 0 );
					ev = BifType::Enum::Input::Event->GetVal(BifEnum::Input::EVENT_CHANGED);
					assert ( oldval != 0 );
					SendEvent(stream->event, 4, stream->description->Ref(),
							ev, predidx, oldval);
					}
				else
					{
					ev = BifType::Enum::Input::Event->GetVal(BifEnum::Input::EVENT_NEW);
					if ( stream->num_val_fields == 0 )
						SendEvent(stream->event, 4, stream->description->Ref(),
								ev, predidx);
					else
						SendEvent(stream->event, 4, stream->description->Ref(),
								ev, predidx, valval->Ref());
					}
				}

			}

		}

	else // no predicates or other stuff
		stream->tab->Assign(idxval, valval);

	Unref(idxval); // not consumed by assign

	return stream->num_idx_fields + stream->num_val_fields;
	}

// Todo:: perhaps throw some kind of clear-event?
void Manager::Clear(ReaderFrontend* reader)
	{
	Stream *i = FindStream(reader);
	if ( i == 0 )
		{
		reporter->InternalWarning("Unknown reader %s in Clear",
		                          reader->Name());
		return;
		}

#ifdef DEBUG
		DBG_LOG(DBG_INPUT, "Got Clear for stream %s",
			i->name.c_str());
#endif

	assert(i->stream_type == TABLE_STREAM);
	TableStream* stream = (TableStream*) i;

	stream->tab->RemoveAll();
	}

// put interface: delete old entry from table.
bool Manager::Delete(ReaderFrontend* reader, Value* *vals)
	{
	Stream *i = FindStream(reader);
	if ( i == 0 )
		{
		reporter->InternalWarning("Unknown reader %s in Delete", reader->Name());
		return false;
		}

	bool success = false;
	int readVals = 0;

	if ( i->stream_type == TABLE_STREAM )
		{
		TableStream* stream = (TableStream*) i;
		bool convert_error = false;
		Val* idxval = ValueToIndexVal(i, stream->num_idx_fields, stream->itype, vals, convert_error);
		assert(idxval != 0);
		readVals = stream->num_idx_fields + stream->num_val_fields;
		bool streamresult = true;

		if ( convert_error )
			{
			Unref(idxval);
			return false;
			}

		if ( stream->pred || stream->event )
			{
			Val *val = stream->tab->Lookup(idxval);

			if ( stream->pred )
				{
				int startpos = 0;
				Val* predidx = ValueToRecordVal(i, vals, stream->itype, &startpos, convert_error);

				if ( convert_error )
					Unref(predidx);
				else
					{
					Ref(val);
					EnumVal *ev = BifType::Enum::Input::Event->GetVal(BifEnum::Input::EVENT_REMOVED);

					streamresult = CallPred(stream->pred, 3, ev, predidx, val);

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
				assert(val != 0);
				Ref(val);
				EnumVal *ev = BifType::Enum::Input::Event->GetVal(BifEnum::Input::EVENT_REMOVED);
				SendEvent(stream->event, 4, stream->description->Ref(), ev, idxval, val);
				}
			}

		// only if stream = true -> no streaming
		if ( streamresult )
			{
			Val* retptr = stream->tab->Delete(idxval);
			success = ( retptr != 0 );
			if ( ! success )
				Warning(i, "Internal error while deleting values from input table");
			else
				Unref(retptr);
			}

		}

	else if ( i->stream_type == EVENT_STREAM  )
		{
		EnumVal *type = BifType::Enum::Input::Event->GetVal(BifEnum::Input::EVENT_REMOVED);
		readVals = SendEventStreamEvent(i, type, vals);
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

	delete_value_ptr_array(vals, readVals);
	return success;
	}

bool Manager::CallPred(Func* pred_func, const int numvals, ...) const
	{
	bool result = false;
	val_list vl(numvals);

	va_list lP;
	va_start(lP, numvals);
	for ( int i = 0; i < numvals; i++ )
		vl.push_back( va_arg(lP, Val*) );

	va_end(lP);

	Val* v = pred_func->Call(&vl);
	if ( v )
		{
		result = v->AsBool();
		Unref(v);
		}

	return result;
	}

// Raise everything in here as warnings so it is passed to scriptland without
// looking "fatal". In addition to these warnings, ReaderBackend will queue
// one reporter message.
bool Manager::SendEvent(ReaderFrontend* reader, const string& name, const int num_vals, Value* *vals) const
	{
	Stream *i = FindStream(reader);
	if ( i == 0 )
		{
		reporter->InternalWarning("Unknown reader %s in SendEvent for event %s", reader->Name(), name.c_str());
		delete_value_ptr_array(vals, num_vals);
		return false;
		}

	EventHandler* handler = event_registry->Lookup(name);
	if ( handler == 0 )
		{
		Warning(i, "Event %s not found", name.c_str());
		delete_value_ptr_array(vals, num_vals);
		return false;
		}

#ifdef DEBUG
	DBG_LOG(DBG_INPUT, "SendEvent for event %s with %d vals",
		name.c_str(), num_vals);
#endif

	RecordType *type = handler->FType()->Args();
	int num_event_vals = type->NumFields();
	if ( num_vals != num_event_vals )
		{
		Warning(i, "Wrong number of values for event %s", name.c_str());
		delete_value_ptr_array(vals, num_vals);
		return false;
		}

	bool convert_error = false;

	val_list vl(num_vals);

	for ( int j = 0; j < num_vals; j++)
		{
		Val* v = ValueToVal(i, vals[j], convert_error);
		vl.push_back(v);
		if ( v && ! convert_error && ! same_type(type->FieldType(j), v->Type()) )
			{
			convert_error = true;
			type->FieldType(j)->Error("SendEvent types do not match", v->Type());
			}
		}

	delete_value_ptr_array(vals, num_vals);

	if ( convert_error )
		{
		for ( const auto& v : vl )
			Unref(v);

		return false;
		}
	else
		mgr.QueueEvent(handler, std::move(vl), SOURCE_LOCAL);

	return true;
}

void Manager::SendEvent(EventHandlerPtr ev, const int numvals, ...) const
	{
	val_list vl(numvals);

#ifdef DEBUG
	DBG_LOG(DBG_INPUT, "SendEvent with %d vals",
		numvals);
#endif

	va_list lP;
	va_start(lP, numvals);
	for ( int i = 0; i < numvals; i++ )
		vl.push_back( va_arg(lP, Val*) );

	va_end(lP);

	mgr.QueueEvent(ev, std::move(vl), SOURCE_LOCAL);
	}

void Manager::SendEvent(EventHandlerPtr ev, list<Val*> events) const
	{
	val_list vl(events.size());

#ifdef DEBUG
	DBG_LOG(DBG_INPUT, "SendEvent with %" PRIuPTR " vals (list)",
		events.size());
#endif

	for ( list<Val*>::iterator i = events.begin(); i != events.end(); i++ )
		vl.push_back( *i );

	mgr.QueueEvent(ev, std::move(vl), SOURCE_LOCAL);
	}

// Convert a bro list value to a bro record value.
// I / we could think about moving this functionality to val.cc
RecordVal* Manager::ListValToRecordVal(ListVal* list, RecordType *request_type, int* position) const
	{
	assert(position != 0 ); // we need the pointer to point to data;

	RecordVal* rec = new RecordVal(request_type->AsRecordType());

	assert(list != 0);
	int maxpos = list->Length();

	for ( int i = 0; i < request_type->NumFields(); i++ )
		{
		assert ( (*position) <= maxpos );

		Val* fieldVal = 0;
		if ( request_type->FieldType(i)->Tag() == TYPE_RECORD )
			fieldVal = ListValToRecordVal(list, request_type->FieldType(i)->AsRecordType(), position);
		else
			{
			fieldVal = list->Index(*position);
			(*position)++;
			}

		rec->Assign(i, fieldVal->Ref());
		}

	return rec;
	}

// Convert a threading value to a record value
RecordVal* Manager::ValueToRecordVal(const Stream* stream, const Value* const *vals,
	                             RecordType *request_type, int* position, bool& have_error) const
	{
	assert(position != 0); // we need the pointer to point to data.

	RecordVal* rec = new RecordVal(request_type->AsRecordType());
	for ( int i = 0; i < request_type->NumFields(); i++ )
		{
		Val* fieldVal = 0;
		if ( request_type->FieldType(i)->Tag() == TYPE_RECORD )
			fieldVal = ValueToRecordVal(stream, vals, request_type->FieldType(i)->AsRecordType(), position, have_error);
		else if ( request_type->FieldType(i)->Tag() == TYPE_FILE ||
			  request_type->FieldType(i)->Tag() == TYPE_FUNC )
			{
			// If those two unsupported types are encountered here, they have
			// been let through by the type checking.
			// That means that they are optional & the user agreed to ignore
			// them and has been warned by reporter.
			// Hence -> assign null to the field, done.

			// Better check that it really is optional. Uou never know.
			assert(request_type->FieldDecl(i)->FindAttr(ATTR_OPTIONAL));
			}
		else
			{
			fieldVal = ValueToVal(stream, vals[*position], request_type->FieldType(i), have_error);
			(*position)++;
			}

		if ( fieldVal )
			rec->Assign(i, fieldVal);
		}

	return rec;
	}

// Count the length of the values used to create a correct length buffer for
// hashing later
int Manager::GetValueLength(const Value* val) const
	{
	assert( val->present ); // presence has to be checked elsewhere
	int length = 0;

	switch (val->type) {
	case TYPE_BOOL:
	case TYPE_INT:
		length += sizeof(val->val.int_val);
		break;

	case TYPE_COUNT:
	case TYPE_COUNTER:
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
		switch ( val->val.addr_val.family ) {
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
		switch ( val->val.subnet_val.prefix.family ) {
		case IPv4:
			length += sizeof(val->val.subnet_val.prefix.in.in4)+
				  sizeof(val->val.subnet_val.length);
			break;
		case IPv6:
			length += sizeof(val->val.subnet_val.prefix.in.in6)+
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

// Given a threading::value, copy the raw data bytes into *data and return how many bytes were copied.
// Used for hashing the values for lookup in the bro table
int Manager::CopyValue(char *data, const int startpos, const Value* val) const
	{
	assert( val->present ); // presence has to be checked elsewhere

	switch ( val->type ) {
	case TYPE_BOOL:
	case TYPE_INT:
		memcpy(data+startpos, (const void*) &(val->val.int_val), sizeof(val->val.int_val));
		return sizeof(val->val.int_val);

	case TYPE_COUNT:
	case TYPE_COUNTER:
		memcpy(data+startpos, (const void*) &(val->val.uint_val), sizeof(val->val.uint_val));
		return sizeof(val->val.uint_val);

	case TYPE_PORT:
		{
		int length = 0;
		memcpy(data+startpos, (const void*) &(val->val.port_val.port),
		       sizeof(val->val.port_val.port));
		length += sizeof(val->val.port_val.port);
		memcpy(data+startpos+length, (const void*) &(val->val.port_val.proto),
		       sizeof(val->val.port_val.proto));
		length += sizeof(val->val.port_val.proto);
		return length;
		}


	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
		memcpy(data+startpos, (const void*) &(val->val.double_val),
		       sizeof(val->val.double_val));
		return sizeof(val->val.double_val);

	case TYPE_STRING:
	case TYPE_ENUM:
		{
		memcpy(data+startpos, val->val.string_val.data, val->val.string_val.length);
		// Add a \0 to the end. To be able to hash zero-length
		// strings and differentiate from !present.
		memset(data + startpos + val->val.string_val.length, 0, 1);
		return val->val.string_val.length + 1;
		}

	case TYPE_ADDR:
		{
		int length = 0;
		switch ( val->val.addr_val.family ) {
		case IPv4:
			length = sizeof(val->val.addr_val.in.in4);
			memcpy(data + startpos, (const char*) &(val->val.addr_val.in.in4), length);
			break;

		case IPv6:
			length = sizeof(val->val.addr_val.in.in6);
			memcpy(data + startpos, (const char*) &(val->val.addr_val.in.in6), length);
			break;

		default:
			assert(false);
		}

		return length;
		}

	case TYPE_SUBNET:
		{
		int length = 0;
		switch ( val->val.subnet_val.prefix.family ) {
		case IPv4:
			length = sizeof(val->val.addr_val.in.in4);
			memcpy(data + startpos,
			       (const char*) &(val->val.subnet_val.prefix.in.in4), length);
			break;

		case IPv6:
			length = sizeof(val->val.addr_val.in.in6);
			memcpy(data + startpos,
			       (const char*) &(val->val.subnet_val.prefix.in.in6), length);
			break;

		default:
			assert(false);
		}

		int lengthlength = sizeof(val->val.subnet_val.length);
		memcpy(data + startpos + length ,
		       (const char*) &(val->val.subnet_val.length), lengthlength);
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
			length += CopyValue(data, startpos+length, val->val.set_val.vals[i]);

		return length;
		}

	case TYPE_VECTOR:
		{
		int length = 0;
		int j = val->val.vector_val.size;
		for ( int i = 0; i < j; i++ )
			length += CopyValue(data, startpos+length, val->val.vector_val.vals[i]);

		return length;
		}

	default:
		reporter->InternalError("unsupported type %d for CopyValue", val->type);
		return 0;
	}

	assert(false);
	return 0;
	}

// Hash num_elements threading values and return the HashKey for them. At least one of the vals has to be ->present.
HashKey* Manager::HashValues(const int num_elements, const Value* const *vals) const
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

	assert ( length >= num_elements );

	if ( length == num_elements )
		return NULL;

	int position = 0;
	char *data = new char[length];

	for ( int i = 0; i < num_elements; i++ )
		{
		const Value* val = vals[i];
		if ( val->present )
			position += CopyValue(data, position, val);

		memset(data + position, 1, 1); // Add end-of-field-marker. Does not really matter which value it is,
		                               // it just has to be... something.

		position++;

		}

	HashKey *key = new HashKey(data, length);
	delete [] data;

	assert(position == length);
	return key;
	}

// convert threading value to Bro value
// have_error is a reference to a boolean which is set to true as soon as an error occured.
// When have_error is set to true at the beginning of the function, it is assumed that
// an error already occured in the past and processing is aborted.
Val* Manager::ValueToVal(const Stream* i, const Value* val, BroType* request_type, bool& have_error) const
	{
	if ( have_error )
		return nullptr;

	if ( request_type->Tag() != TYPE_ANY && request_type->Tag() != val->type )
		{
		reporter->InternalError("Typetags don't match: %d vs %d in stream %s", request_type->Tag(), val->type, i->name.c_str());
		return nullptr;
		}

	if ( !val->present )
		return nullptr; // unset field

	switch ( val->type ) {
	case TYPE_BOOL:
		return val_mgr->GetBool(val->val.int_val);

	case TYPE_INT:
		return val_mgr->GetInt(val->val.int_val);

	case TYPE_COUNT:
	case TYPE_COUNTER:
		return val_mgr->GetCount(val->val.int_val);

	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
		return new Val(val->val.double_val, val->type);

	case TYPE_STRING:
		{
		BroString *s = new BroString((const u_char*)val->val.string_val.data, val->val.string_val.length, 1);
		return new StringVal(s);
		}

	case TYPE_PORT:
		return val_mgr->GetPort(val->val.port_val.port, val->val.port_val.proto);

	case TYPE_ADDR:
		{
		IPAddr* addr = 0;
		switch ( val->val.addr_val.family ) {
		case IPv4:
			addr = new IPAddr(val->val.addr_val.in.in4);
			break;

		case IPv6:
			addr = new IPAddr(val->val.addr_val.in.in6);
			break;

		default:
			assert(false);
		}

		AddrVal* addrval = new AddrVal(*addr);
		delete addr;
		return addrval;
		}

	case TYPE_SUBNET:
		{
		IPAddr* addr = nullptr;
		switch ( val->val.subnet_val.prefix.family ) {
		case IPv4:
			addr = new IPAddr(val->val.subnet_val.prefix.in.in4);
			break;

		case IPv6:
			addr = new IPAddr(val->val.subnet_val.prefix.in.in6);
			break;

		default:
			assert(false);
		}

		SubNetVal* subnetval = new SubNetVal(*addr, val->val.subnet_val.length);
		delete addr;
		return subnetval;
		}

	case TYPE_PATTERN:
		{
		RE_Matcher* re = new RE_Matcher(val->val.pattern_text_val);
		re->Compile();
		return new PatternVal(re);
		}

	case TYPE_TABLE:
		{
		// all entries have to have the same type...
		BroType* type = request_type->AsTableType()->Indices()->PureType();
		TypeList* set_index = new TypeList(type->Ref());
		set_index->Append(type->Ref());
		SetType* s = new SetType(set_index, 0);
		TableVal* t = new TableVal(s);
		for ( int j = 0; j < val->val.set_val.size; j++ )
			{
			Val* assignval = ValueToVal(i, val->val.set_val.vals[j], type, have_error);

			t->Assign(assignval, 0);
			Unref(assignval); // index is not consumed by assign.
			}

		Unref(s);
		return t;
		}

	case TYPE_VECTOR:
		{
		// all entries have to have the same type...
		BroType* type = request_type->AsVectorType()->YieldType();
		VectorType* vt = new VectorType(type->Ref());
		VectorVal* v = new VectorVal(vt);
		for ( int j = 0; j < val->val.vector_val.size; j++ )
			{
			v->Assign(j, ValueToVal(i, val->val.vector_val.vals[j], type, have_error));
			}

		Unref(vt);
		return v;
		}

	case TYPE_ENUM: {
		// Convert to string first to not have to deal with missing
		// \0's...
		string enum_string(val->val.string_val.data, val->val.string_val.length);

		string module = extract_module_name(enum_string.c_str());
		string var = extract_var_name(enum_string.c_str());

		// Well, this is kind of stupid, because EnumType just
		// mangles the module name and the var name together again...
		// but well.
		bro_int_t index = request_type->AsEnumType()->Lookup(module, var.c_str());
		if ( index == -1 )
			{
			Warning(i, "Value '%s' for stream '%s' is not a valid enum.",
			                        enum_string.c_str(), i->name.c_str());

			have_error = true;
			return nullptr;
			}

		return request_type->Ref()->AsEnumType()->GetVal(index);
		}

	default:
		reporter->InternalError("Unsupported type for input_read in stream %s", i->name.c_str());
	}

	assert(false);
	return NULL;
	}

Val* Manager::ValueToVal(const Stream* i, const Value* val, bool& have_error) const
	{
	if ( have_error )
		return nullptr;

	if ( ! val->present )
		return nullptr; // unset field

	switch ( val->type ) {
	case TYPE_BOOL:
		return val_mgr->GetBool(val->val.int_val);

	case TYPE_INT:
		return val_mgr->GetInt(val->val.int_val);

	case TYPE_COUNT:
	case TYPE_COUNTER:
		return val_mgr->GetCount(val->val.int_val);

	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
		return new Val(val->val.double_val, val->type);

	case TYPE_STRING:
		{
		BroString *s = new BroString((const u_char*)val->val.string_val.data, val->val.string_val.length, 1);
		return new StringVal(s);
		}

	case TYPE_PORT:
		return val_mgr->GetPort(val->val.port_val.port, val->val.port_val.proto);

	case TYPE_ADDR:
		{
		IPAddr* addr = 0;
		switch ( val->val.addr_val.family ) {
		case IPv4:
			addr = new IPAddr(val->val.addr_val.in.in4);
			break;

		case IPv6:
			addr = new IPAddr(val->val.addr_val.in.in6);
			break;

		default:
			assert(false);
		}

		AddrVal* addrval = new AddrVal(*addr);
		delete addr;
		return addrval;
		}

	case TYPE_SUBNET:
		{
		IPAddr* addr = nullptr;
		switch ( val->val.subnet_val.prefix.family ) {
		case IPv4:
			addr = new IPAddr(val->val.subnet_val.prefix.in.in4);
			break;

		case IPv6:
			addr = new IPAddr(val->val.subnet_val.prefix.in.in6);
			break;

		default:
			assert(false);
		}

		SubNetVal* subnetval = new SubNetVal(*addr, val->val.subnet_val.length);
		delete addr;
		return subnetval;
		}

	case TYPE_PATTERN:
		{
		RE_Matcher* re = new RE_Matcher(val->val.pattern_text_val);
		re->Compile();
		return new PatternVal(re);
		}

	case TYPE_TABLE:
		{
		TypeList* set_index;
		if ( val->val.set_val.size == 0 && val->subtype == TYPE_VOID )
			// don't know type - unspecified table.
			set_index = new TypeList();
		else
			{
			// all entries have to have the same type...
			TypeTag stag = val->subtype;
			if ( stag == TYPE_VOID )
				TypeTag stag = val->val.set_val.vals[0]->type;

			BroType* index_type;

			if ( stag == TYPE_ENUM )
				{
				// Enums are not a base-type, so need to look it up.
				const auto& sv = val->val.set_val.vals[0]->val.string_val;
				std::string enum_name(sv.data, sv.length);
				auto enum_id = global_scope()->Lookup(enum_name);

				if ( ! enum_id )
					{
					Warning(i, "Value '%s' for stream '%s' is not a valid enum.",
					        enum_name.data(), i->name.c_str());

					have_error = true;
					return nullptr;
					}

				index_type = enum_id->Type()->AsEnumType();
				}
			else
				index_type = base_type_no_ref(stag);

			set_index = new TypeList(index_type);
			set_index->Append(index_type->Ref());
			}

		SetType* s = new SetType(set_index, 0);
		TableVal* t = new TableVal(s);
		for ( int j = 0; j < val->val.set_val.size; j++ )
			{
			Val* assignval = ValueToVal(i, val->val.set_val.vals[j], have_error);

			t->Assign(assignval, 0);
			Unref(assignval); // index is not consumed by assign.
			}

		Unref(s);
		return t;
		}

	case TYPE_VECTOR:
		{
		BroType* type;
		if ( val->val.vector_val.size == 0  && val->subtype == TYPE_VOID )
			// don't know type - unspecified table.
			type = base_type(TYPE_ANY);
		else
			{
			// all entries have to have the same type...
			if ( val->subtype == TYPE_VOID )
				type = base_type(val->val.vector_val.vals[0]->type);
			else
				type = base_type(val->subtype);
			}

		VectorType* vt = new VectorType(type->Ref());
		VectorVal* v = new VectorVal(vt);
		for ( int j = 0; j < val->val.vector_val.size; j++ )
			{
			v->Assign(j, ValueToVal(i, val->val.vector_val.vals[j], have_error));
			}

		Unref(vt);
		return v;
		}

	case TYPE_ENUM: {
		// Convert to string first to not have to deal with missing
		// \0's...
		string enum_string(val->val.string_val.data, val->val.string_val.length);

		// let's try looking it up by global ID.
		ID* id = lookup_ID(enum_string.c_str(), GLOBAL_MODULE_NAME);
		if ( ! id || ! id->IsEnumConst() )
			{
			Warning(i, "Value '%s' for stream '%s' is not a valid enum.",
			                        enum_string.c_str(), i->name.c_str());

			have_error = true;
			return nullptr;
			}

		EnumType* t = id->Type()->AsEnumType();
		int intval = t->Lookup(id->ModuleName(), id->Name());
		if ( intval < 0 )
			{
			Warning(i, "Enum value '%s' for stream '%s' not found.",
			                        enum_string.c_str(), i->name.c_str());

			have_error = true;
			return nullptr;
			}

		return t->GetVal(intval);
		}

	default:
		reporter->InternalError("Unsupported type for input_read in stream %s", i->name.c_str());
	}

	assert(false);
	return NULL;
	}

Manager::Stream* Manager::FindStream(const string &name) const
	{
	for ( auto s = readers.begin(); s != readers.end(); ++s )
		{
		if ( (*s).second->name  == name )
			return (*s).second;
		}

	return 0;
	}

Manager::Stream* Manager::FindStream(ReaderFrontend* reader) const
	{
	auto s = readers.find(reader);
	if ( s != readers.end() )
		return s->second;

	return 0;
	}

// Function is called on Bro shutdown.
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
	Stream *i = FindStream(reader);
	if ( !i )
		{
		reporter->Error("Stream not found in Info; lost message: %s", msg);
		return;
		}

	ErrorHandler(i, ErrorType::INFO, false, "%s", msg);
	}

void Manager::Warning(ReaderFrontend* reader, const char* msg) const
	{
	Stream *i = FindStream(reader);
	if ( !i )
		{
		reporter->Error("Stream not found in Warning; lost message: %s", msg);
		return;
		}

	ErrorHandler(i, ErrorType::WARNING, false, "%s", msg);
	}

void Manager::Error(ReaderFrontend* reader, const char* msg) const
	{
	Stream *i = FindStream(reader);
	if ( !i )
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

void Manager::ErrorHandler(const Stream* i, ErrorType et, bool reporter_send, const char* fmt, ...) const
	{
	va_list ap;
	va_start(ap, fmt);
	ErrorHandler(i, et, reporter_send, fmt, ap);
	va_end(ap);
	}

void Manager::ErrorHandler(const Stream* i, ErrorType et, bool reporter_send, const char* fmt, va_list ap) const
	{
	char* buf;

	int n = vasprintf(&buf, fmt, ap);
	if ( n < 0 || buf == nullptr )
		{
		reporter->InternalError("Could not format error message %s for stream %s", fmt, i->name.c_str());
		return;
		}

	// send our script level error event
	if ( i->error_event )
		{
		EnumVal* ev;
		switch (et)
			{
			case ErrorType::INFO:
				ev = BifType::Enum::Reporter::Level->GetVal(BifEnum::Reporter::INFO);
				break;

			case ErrorType::WARNING:
				ev = BifType::Enum::Reporter::Level->GetVal(BifEnum::Reporter::WARNING);
				break;

			case ErrorType::ERROR:
				ev = BifType::Enum::Reporter::Level->GetVal(BifEnum::Reporter::ERROR);
				break;

			default:
				reporter->InternalError("Unknown error type while trying to report input error %s", fmt);
				__builtin_unreachable();
			}

		StringVal* message = new StringVal(buf);
		SendEvent(i->error_event, 3, i->description->Ref(), message, ev);
		}

	if ( reporter_send )
		{
		switch (et)
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
				reporter->InternalError("Unknown error type while trying to report input error %s", fmt);
			}
		}

	free(buf);
	}
