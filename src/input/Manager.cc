// See the file "COPYING" in the main distribution directory for copyright.

#include <algorithm>

#include "Manager.h"
#include "ReaderFrontend.h"
#include "ReaderBackend.h"
#include "readers/Ascii.h"
#include "readers/Raw.h"
#include "readers/Benchmark.h"

#include "Event.h"
#include "EventHandler.h"
#include "NetVar.h"
#include "Net.h"


#include "CompHash.h"

#include "../threading/SerialTypes.h"

using namespace input;
using threading::Value;
using threading::Field;

struct InputHash {
	hash_t valhash;
	HashKey* idxkey; 
	~InputHash();
};

InputHash::~InputHash() {
	if ( idxkey )
		delete idxkey;
} 

declare(PDict, InputHash);

class Manager::Filter {
public:
	string name;
	string source;
	bool removed;
	
	int mode;

	FilterType filter_type; // to distinguish between event and table filters

	EnumVal* type;
	ReaderFrontend* reader;

	RecordVal* description;

        Filter();
	virtual ~Filter();
};

Manager::Filter::Filter() {
        type = 0;
        reader = 0;
        description = 0;
	removed = false;
}

Manager::Filter::~Filter() {
        if ( type )
	        Unref(type);
        if ( description )
	        Unref(description);

        if ( reader )
	        delete(reader);	
}

class Manager::TableFilter: public Manager::Filter {
public:

	unsigned int num_idx_fields;
	unsigned int num_val_fields;
	bool want_record;
	EventHandlerPtr table_event;	

	TableVal* tab;
	RecordType* rtype;
	RecordType* itype;

	PDict(InputHash)* currDict;
	PDict(InputHash)* lastDict;

	Func* pred;	

	EventHandlerPtr event;		

	TableFilter();
	~TableFilter();
};

class Manager::EventFilter: public Manager::Filter {
public:
	EventHandlerPtr event;

	RecordType* fields;
	unsigned int num_fields;

	bool want_record;	
	EventFilter();
        ~EventFilter();
};

Manager::TableFilter::TableFilter() : Manager::Filter::Filter() {
	filter_type = TABLE_FILTER;
	
	tab = 0;
	itype = 0;
	rtype = 0;

        currDict = 0;
        lastDict = 0;

        pred = 0;
}

Manager::EventFilter::EventFilter() : Manager::Filter::Filter() {
        fields = 0;
	filter_type = EVENT_FILTER;
}

Manager::EventFilter::~EventFilter() {
        if ( fields ) {
                Unref(fields);
        }
}

Manager::TableFilter::~TableFilter() {
        if ( tab )
	        Unref(tab);
        if ( itype ) 
	        Unref(itype);
	if ( rtype ) // can be 0 for sets
		Unref(rtype);

        if ( currDict != 0 ) {
		currDict->Clear();
	        delete currDict;
	}

        if ( lastDict != 0 ) {
		lastDict->Clear();;
	        delete lastDict;
	}
} 

struct ReaderDefinition {
	bro_int_t type; // the type
	const char *name; // descriptive name for error messages
	bool (*init)(); // optional one-time inifializing function
	ReaderBackend* (*factory)(ReaderFrontend* frontend);	// factory function for creating instances
};

ReaderDefinition input_readers[] = {
	{ BifEnum::Input::READER_ASCII, "Ascii", 0, reader::Ascii::Instantiate },
	{ BifEnum::Input::READER_RAW, "Raw", 0, reader::Raw::Instantiate },
	{ BifEnum::Input::READER_BENCHMARK, "Benchmark", 0, reader::Benchmark::Instantiate },
	
	// End marker
	{ BifEnum::Input::READER_DEFAULT, "None", 0, (ReaderBackend* (*)(ReaderFrontend* frontend))0 }
};

Manager::Manager()
{
}

ReaderBackend* Manager::CreateBackend(ReaderFrontend* frontend, bro_int_t type) {
	ReaderDefinition* ir = input_readers;

	while ( true ) {
		if ( ir->type == BifEnum::Input::READER_DEFAULT ) 
		{
			reporter->Error("The reader that was requested was not found and could not be initialized.");
			return 0;
		}

		if ( ir->type != type ) {
			// no, didn't find the right one...
			++ir;
			continue;
		}

		
		// call init function of writer if presnt
		if ( ir->init ) 
		{
			if ( (*ir->init)() ) 
				{
					//clear it to be not called again
					ir->init = 0;
				} else {
					// ohok. init failed, kill factory for all eternity
					ir->factory = 0;
					DBG_LOG(DBG_LOGGING, "Failed to init input class %s", ir->name);
					return 0;
				}
				
		}
		
		if ( !ir->factory ) 
			// no factory?
			return 0;
		
		// all done. break.
		break;
	}
	assert(ir->factory);

	ReaderBackend* backend = (*ir->factory)(frontend);
	assert(backend);

	frontend->ty_name = ir->name;
	return backend;
}

// create a new input reader object to be used at whomevers leisure lateron.
bool Manager::CreateStream(Filter* info, RecordVal* description) 
{
	ReaderDefinition* ir = input_readers;
	
	RecordType* rtype = description->Type()->AsRecordType();
	if ( ! ( same_type(rtype, BifType::Record::Input::TableDescription, 0)  || same_type(rtype, BifType::Record::Input::EventDescription, 0) ) )
	{
		reporter->Error("Streamdescription argument not of right type for new input stream");
		return false;
	}
	
	Val* name_val = description->LookupWithDefault(rtype->FieldOffset("name"));
	string name = name_val->AsString()->CheckString();
	Unref(name_val);

	{
		Filter *i = FindFilter(name);
		if ( i != 0 ) {
			reporter->Error("Trying create already existing input stream %s", name.c_str());
			return false;
		}
	}

	EnumVal* reader = description->LookupWithDefault(rtype->FieldOffset("reader"))->AsEnumVal();
	Val *autostart = description->LookupWithDefault(rtype->FieldOffset("autostart"));	

        ReaderFrontend* reader_obj = new ReaderFrontend(reader->InternalInt());
        assert(reader_obj);	
	
	// get the source...
	Val* sourceval = description->LookupWithDefault(rtype->FieldOffset("source"));
	assert ( sourceval != 0 );
	const BroString* bsource = sourceval->AsString();
	string source((const char*) bsource->Bytes(), bsource->Len());
	Unref(sourceval);
	
	EnumVal* mode = description->LookupWithDefault(rtype->FieldOffset("mode"))->AsEnumVal();
	info->mode = mode->InternalInt();
	Unref(mode);

	info->reader = reader_obj;
	info->type = reader->AsEnumVal(); // ref'd by lookupwithdefault
	info->name = name;
	info->source = source;
	Ref(description);
	info->description = description;

	DBG_LOG(DBG_INPUT, "Successfully created new input stream %s",
		name.c_str());
	
	return true;
	
}

bool Manager::CreateEventStream(RecordVal* fval) {

	RecordType* rtype = fval->Type()->AsRecordType();
	if ( ! same_type(rtype, BifType::Record::Input::EventDescription, 0) )
	{
		reporter->Error("filter argument not of right type");
		return false;
	}
	
	EventFilter* filter = new EventFilter();
	{
		bool res = CreateStream(filter, fval);
		if ( res == false ) {
			delete filter;
			return false;
		}
	}


	RecordType *fields = fval->LookupWithDefault(rtype->FieldOffset("fields"))->AsType()->AsTypeType()->Type()->AsRecordType();	
	
	Val *want_record = fval->LookupWithDefault(rtype->FieldOffset("want_record"));	

	Val* event_val = fval->LookupWithDefault(rtype->FieldOffset("ev"));
	Func* event = event_val->AsFunc();
	Unref(event_val);

	{
		FuncType* etype = event->FType()->AsFuncType();
		
		if ( ! etype->IsEvent() ) {
			reporter->Error("stream event is a function, not an event");
			return false;
		}

		const type_list* args = etype->ArgTypes()->Types();

		if ( args->length() < 2 ) {
			reporter->Error("event takes not enough arguments");
			return false;
		}

		if ( ! same_type((*args)[1], BifType::Enum::Input::Event, 0) ) 
		{
			reporter->Error("events second attribute must be of type Input::Event");
			return false;
		} 				
		
		if ( ! same_type((*args)[0], BifType::Record::Input::EventDescription, 0) ) 
		{
			reporter->Error("events first attribute must be of type Input::EventDescription");
			return false;
		} 			

		if ( want_record->InternalInt() == 0 ) {
			if ( args->length() != fields->NumFields() + 2 ) {
				reporter->Error("event has wrong number of arguments");
				return false;
			}

			for ( int i = 0; i < fields->NumFields(); i++ ) {
				if ( !same_type((*args)[i+2], fields->FieldType(i) ) ) {
					reporter->Error("Incompatible type for event");
					return false;
				}
			}

		} else if ( want_record->InternalInt() == 1 ) {
			if ( args->length() != 3 ) {
				reporter->Error("event has wrong number of arguments");
				return false;
			}

			if ( !same_type((*args)[2], fields ) ) {
				reporter->Error("Incompatible type for event");
				return false;
			}
			
		} else {
			assert(false);
		}

	}	


	vector<Field*> fieldsV; // vector, because UnrollRecordType needs it

	bool status = !UnrollRecordType(&fieldsV, fields, "");

	if ( status ) {
		reporter->Error("Problem unrolling");
		return false;
	}
	
	Field** logf = new Field*[fieldsV.size()];
	for ( unsigned int i = 0; i < fieldsV.size(); i++ ) {
		logf[i] = fieldsV[i];
	}

	Unref(fields); // ref'd by lookupwithdefault
	filter->num_fields = fieldsV.size();
	filter->fields = fields->Ref()->AsRecordType();
	filter->event = event_registry->Lookup(event->GetID()->Name());
	filter->want_record = ( want_record->InternalInt() == 1 );
	Unref(want_record); // ref'd by lookupwithdefault

	assert(filter->reader);
	filter->reader->Init(filter->source, filter->mode, filter->num_fields, logf );

	readers[filter->reader] = filter;

	DBG_LOG(DBG_INPUT, "Successfully created event stream %s",
		filter->name.c_str());

	return true;
}

bool Manager::CreateTableStream(RecordVal* fval) {
	RecordType* rtype = fval->Type()->AsRecordType();
	if ( ! same_type(rtype, BifType::Record::Input::TableDescription, 0) )
	{
		reporter->Error("filter argument not of right type");
		return false;
	}

	TableFilter* filter = new TableFilter();
	{
		bool res = CreateStream(filter, fval);
		if ( res == false ) {
			delete filter;
			return false;
		}
	}

	Val* pred = fval->LookupWithDefault(rtype->FieldOffset("pred"));

	RecordType *idx = fval->LookupWithDefault(rtype->FieldOffset("idx"))->AsType()->AsTypeType()->Type()->AsRecordType();
	RecordType *val = 0;
	if ( fval->LookupWithDefault(rtype->FieldOffset("val")) != 0 ) {
		val = fval->LookupWithDefault(rtype->FieldOffset("val"))->AsType()->AsTypeType()->Type()->AsRecordType();
		Unref(val); // The lookupwithdefault in the if-clause ref'ed val.
	}
	TableVal *dst = fval->LookupWithDefault(rtype->FieldOffset("destination"))->AsTableVal();

	// check if index fields match table description
	{
		int num = idx->NumFields();
		const type_list* tl = dst->Type()->AsTableType()->IndexTypes();

		loop_over_list(*tl, j)
			{
			if ( j >= num ) {
				reporter->Error("Table type has more indexes than index definition");
				return false;
			}

			if ( !same_type(idx->FieldType(j), (*tl)[j]) ) {
				reporter->Error("Table type does not match index type");
				return false;
			}
			}

		if ( num != j ) {
			reporter->Error("Table has less elements than index definition");
			return false;
		}
	}

	Val *want_record = fval->LookupWithDefault(rtype->FieldOffset("want_record"));

	Val* event_val = fval->LookupWithDefault(rtype->FieldOffset("ev"));
	Func* event = event_val ? event_val->AsFunc() : 0;
	Unref(event_val);
	
	if ( event ) {
		FuncType* etype = event->FType()->AsFuncType();
		
		if ( ! etype->IsEvent() ) {
			reporter->Error("stream event is a function, not an event");
			return false;
		}

		const type_list* args = etype->ArgTypes()->Types();

		if ( args->length() != 4 ) 
		{
			reporter->Error("Table event must take 4 arguments");
			return false;
		}

		if ( ! same_type((*args)[0], BifType::Record::Input::TableDescription, 0) ) 
		{
			reporter->Error("table events first attribute must be of type Input::TableDescription");
			return false;
		} 		

		if ( ! same_type((*args)[1], BifType::Enum::Input::Event, 0) ) 
		{
			reporter->Error("table events second attribute must be of type Input::Event");
			return false;
		} 		

		if ( ! same_type((*args)[2], idx) ) 
		{
			reporter->Error("table events index attributes do not match");
			return false;
		} 
		
		if ( want_record->InternalInt() == 1 && ! same_type((*args)[3], val) ) 
		{
			reporter->Error("table events value attributes do not match");
			return false;
		} else if (  want_record->InternalInt() == 0 && !same_type((*args)[3], val->FieldType(0) ) ) {
			reporter->Error("table events value attribute does not match");
			return false;
		}
		assert(want_record->InternalInt() == 1 || want_record->InternalInt() == 0);

	}	

	vector<Field*> fieldsV; // vector, because we don't know the length beforehands

	bool status = !UnrollRecordType(&fieldsV, idx, "");

	int idxfields = fieldsV.size();
	
	if ( val ) // if we are not a set
		status = status || !UnrollRecordType(&fieldsV, val, "");

	int valfields = fieldsV.size() - idxfields;

	if ( !val )
		assert(valfields == 0);

	if ( status ) {
		reporter->Error("Problem unrolling");
		return false;
	}
	
	
	Field** fields = new Field*[fieldsV.size()];
	for ( unsigned int i = 0; i < fieldsV.size(); i++ ) {
		fields[i] = fieldsV[i];
	}
	
	filter->pred = pred ? pred->AsFunc() : 0;
	filter->num_idx_fields = idxfields;
	filter->num_val_fields = valfields;
	filter->tab = dst->AsTableVal();
	filter->rtype = val ? val->AsRecordType() : 0;
	filter->itype = idx->AsRecordType();
	filter->event = event ? event_registry->Lookup(event->GetID()->Name()) : 0;
	filter->currDict = new PDict(InputHash);
	filter->lastDict = new PDict(InputHash);
	filter->want_record = ( want_record->InternalInt() == 1 );

	Unref(want_record); // ref'd by lookupwithdefault
	Unref(pred);

	if ( valfields > 1 ) {
		if ( ! filter->want_record ) {
			reporter->Error("Stream %s does not want a record (want_record=F), but has more then one value field. Aborting", filter->name.c_str());
			delete filter;
			return false;
		}
	}


	assert(filter->reader);
	filter->reader->Init(filter->source, filter->mode, fieldsV.size(), fields );

	readers[filter->reader] = filter;

	DBG_LOG(DBG_INPUT, "Successfully created table stream %s",
		filter->name.c_str());

	return true;
}


bool Manager::IsCompatibleType(BroType* t, bool atomic_only)
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


bool Manager::RemoveStream(const string &name) {
	Filter *i = FindFilter(name);

	if ( i == 0 ) {
		return false; // not found
	}

	if ( i->removed ) {
		reporter->Error("Stream %s is already queued for removal. Ignoring remove.", name.c_str());
		return false;
	}

	i->removed = true;

	i->reader->Finish();

#ifdef DEBUG
		DBG_LOG(DBG_INPUT, "Successfully queued removal of stream %s",
			name.c_str());
#endif

	return true;
}

bool Manager::RemoveStreamContinuation(ReaderFrontend* reader) {
	Filter *i = FindFilter(reader);

	if ( i == 0 ) {
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

bool Manager::UnrollRecordType(vector<Field*> *fields, const RecordType *rec, const string& nameprepend) {
	for ( int i = 0; i < rec->NumFields(); i++ ) 
	{

		if ( !IsCompatibleType(rec->FieldType(i)) ) {
			reporter->Error("Incompatible type \"%s\" in table definition for ReaderFrontend", type_name(rec->FieldType(i)->Tag()));
			return false;
		}

		if ( rec->FieldType(i)->Tag() == TYPE_RECORD ) 
		{
			string prep = nameprepend + rec->FieldName(i) + ".";
			
			if ( !UnrollRecordType(fields, rec->FieldType(i)->AsRecordType(), prep) ) 
			{
				return false;
			}

		} else {
			Field* field = new Field();
			field->name = nameprepend + rec->FieldName(i);
			field->type = rec->FieldType(i)->Tag();	
			if ( field->type == TYPE_TABLE ) {
				field->subtype = rec->FieldType(i)->AsSetType()->Indices()->PureType()->Tag();
			} else if ( field->type == TYPE_VECTOR ) {
				field->subtype = rec->FieldType(i)->AsVectorType()->YieldType()->Tag();
			} else if ( field->type == TYPE_PORT &&
					rec->FieldDecl(i)->FindAttr(ATTR_TYPE_COLUMN) ) {
				// we have an annotation for the second column
				
				Val* c = rec->FieldDecl(i)->FindAttr(ATTR_TYPE_COLUMN)->AttrExpr()->Eval(0);

				assert(c);
				assert(c->Type()->Tag() == TYPE_STRING);

				field->secondary_name = c->AsStringVal()->AsString()->CheckString();
			}

			if ( rec->FieldDecl(i)->FindAttr(ATTR_OPTIONAL ) ) {
				field->optional = true;
			}

			fields->push_back(field);
		}
	}

	return true;
}

bool Manager::ForceUpdate(const string &name)
{
	Filter *i = FindFilter(name);
	if ( i == 0 ) {
		reporter->Error("Stream %s not found", name.c_str());
		return false;
	}
	
	if ( i->removed ) {
		reporter->Error("Stream %s is already queued for removal. Ignoring force update.", name.c_str());
		return false;
	}
 
	i->reader->Update();

#ifdef DEBUG
		DBG_LOG(DBG_INPUT, "Forcing update of stream %s",
			name.c_str());
#endif

	return true; // update is async :(
}


Val* Manager::RecordValToIndexVal(RecordVal *r) {
	Val* idxval;

	RecordType *type = r->Type()->AsRecordType();

	int num_fields = type->NumFields();

	if ( num_fields == 1 && type->FieldDecl(0)->type->Tag() != TYPE_RECORD  ) {
		idxval = r->Lookup(0);
	} else {
		ListVal *l = new ListVal(TYPE_ANY);
		for ( int j = 0 ; j < num_fields; j++ ) {
			//Val* rval = r->Lookup(j);
			//assert(rval != 0);
			l->Append(r->LookupWithDefault(j));
		}
		idxval = l;
	}


	return idxval;
}


Val* Manager::ValueToIndexVal(int num_fields, const RecordType *type, const Value* const *vals) {
	Val* idxval;
	int position = 0;


	if ( num_fields == 1 && type->FieldType(0)->Tag() != TYPE_RECORD  ) {
		idxval = ValueToVal(vals[0], type->FieldType(0));
		position = 1;
	} else {
		ListVal *l = new ListVal(TYPE_ANY);
		for ( int j = 0 ; j < type->NumFields(); j++ ) {
			if ( type->FieldType(j)->Tag() == TYPE_RECORD ) {
				l->Append(ValueToRecordVal(vals, type->FieldType(j)->AsRecordType(), &position));
			} else {
				l->Append(ValueToVal(vals[position], type->FieldType(j)));
				position++;
			}
		}
		idxval = l;
	}

	assert ( position == num_fields );

	return idxval;
}


void Manager::SendEntry(ReaderFrontend* reader, Value* *vals) {
	Filter *i = FindFilter(reader);
	if ( i == 0 ) {
		reporter->InternalError("Unknown reader in SendEntry");
		return;
	}

	int readFields;
	if ( i->filter_type == TABLE_FILTER ) {
		readFields = SendEntryTable(i, vals);
	} else if ( i->filter_type == EVENT_FILTER ) {
		EnumVal *type = new EnumVal(BifEnum::Input::EVENT_NEW, BifType::Enum::Input::Event);
		readFields = SendEventFilterEvent(i, type, vals);		
	} else {
		assert(false);
	}

	for ( int i = 0; i < readFields; i++ ) {
		delete vals[i];
	}
	delete [] vals;	
}

int Manager::SendEntryTable(Filter* i, const Value* const *vals) {
	bool updated = false;

	assert(i);

	assert(i->filter_type == TABLE_FILTER);
	TableFilter* filter = (TableFilter*) i;

	HashKey* idxhash = HashValues(filter->num_idx_fields, vals);
	
	if ( idxhash == 0 ) {
		reporter->Error("Could not hash line. Ignoring");
		return filter->num_val_fields + filter->num_idx_fields;
	}	
	
	hash_t valhash = 0;
	if ( filter->num_val_fields > 0 ) {
		HashKey* valhashkey = HashValues(filter->num_val_fields, vals+filter->num_idx_fields);
		if ( valhashkey == 0 ) {
			// empty line. index, but no values.
			// hence we also have no hash value...
		} else {
	     		valhash = valhashkey->Hash();
	      		delete(valhashkey);
		}
	}

	InputHash *h = filter->lastDict->Lookup(idxhash);
	if ( h != 0 ) {
		// seen before
		if ( filter->num_val_fields == 0 || h->valhash == valhash ) {
			// ok, exact duplicate
			filter->lastDict->Remove(idxhash);
			filter->currDict->Insert(idxhash, h);
			delete idxhash;
			return filter->num_val_fields + filter->num_idx_fields;
		} else {
			assert( filter->num_val_fields > 0 );
			// updated
			filter->lastDict->Remove(idxhash);
			delete(h);
			updated = true;
			
		}
	}


	Val* valval;
	RecordVal* predidx = 0;
	
	int position = filter->num_idx_fields;
	if ( filter->num_val_fields == 0 ) {
		valval = 0;
	} else if ( filter->num_val_fields == 1 && !filter->want_record ) {
		valval = ValueToVal(vals[position], filter->rtype->FieldType(0));
	} else {
		valval = ValueToRecordVal(vals, filter->rtype, &position);
	}



	// call filter first to determine if we really add / change the entry
	if ( filter->pred ) {
		EnumVal* ev;
		//Ref(idxval);
		int startpos = 0; 
		//Val* predidx = ListValToRecordVal(idxval->AsListVal(), filter->itype, &startpos);
		predidx = ValueToRecordVal(vals, filter->itype, &startpos);
		//ValueToRecordVal(vals, filter->itype, &startpos);

		if ( updated ) {
			ev = new EnumVal(BifEnum::Input::EVENT_CHANGED, BifType::Enum::Input::Event);
		} else {
			ev = new EnumVal(BifEnum::Input::EVENT_NEW, BifType::Enum::Input::Event);
		}

		bool result;
		if ( filter->num_val_fields > 0 ) { // we have values
			result = CallPred(filter->pred, 3, ev, predidx->Ref(), valval->Ref());
		} else {
			// no values
			result = CallPred(filter->pred, 2, ev, predidx->Ref());
		}
		
		if ( result == false ) {
			Unref(predidx);
			if ( !updated ) {
				// throw away. Hence - we quit. And remove the entry from the current dictionary...
				delete(filter->currDict->RemoveEntry(idxhash));
				delete idxhash;
				return filter->num_val_fields + filter->num_idx_fields;
			} else {
				// keep old one
				filter->currDict->Insert(idxhash, h);
				delete idxhash;
				return filter->num_val_fields + filter->num_idx_fields;
			}
		}

	} 
	

	Val* idxval;
        if ( predidx != 0 ) {
		idxval = RecordValToIndexVal(predidx);
		// I think there is an unref missing here. But if I insert is, it crashes :)
	} else {
		idxval = ValueToIndexVal(filter->num_idx_fields, filter->itype, vals);
	}
	Val* oldval = 0;
	if ( updated == true ) {
		assert(filter->num_val_fields > 0);
		// in that case, we need the old value to send the event (if we send an event).
		oldval = filter->tab->Lookup(idxval, false);
	}

	//i->tab->Assign(idxval, valval);
	assert(idxval);
	HashKey* k = filter->tab->ComputeHash(idxval);
	if ( !k ) {
		reporter->InternalError("could not hash");
		assert(false);
	}

	InputHash* ih = new InputHash();
	ih->idxkey = new HashKey(k->Key(), k->Size(), k->Hash());
	ih->valhash = valhash;

	if ( filter->event && updated )
		Ref(oldval); // otherwise it is no longer accessible after the assignment
	filter->tab->Assign(idxval, k, valval);
	Unref(idxval); // asssign does not consume idxval.

	filter->currDict->Insert(idxhash, ih);
	delete idxhash;

	if ( filter->event ) {
		EnumVal* ev;
		int startpos = 0;
		Val* predidx = ValueToRecordVal(vals, filter->itype, &startpos);

		if ( updated ) { // in case of update send back the old value.
			assert ( filter->num_val_fields > 0 );
			ev = new EnumVal(BifEnum::Input::EVENT_CHANGED, BifType::Enum::Input::Event);
			assert ( oldval != 0 );
			SendEvent(filter->event, 4, filter->description->Ref(), ev, predidx, oldval);
		} else {
			ev = new EnumVal(BifEnum::Input::EVENT_NEW, BifType::Enum::Input::Event);
			if ( filter->num_val_fields == 0 ) {
				Ref(filter->description);
				SendEvent(filter->event, 3, filter->description->Ref(), ev, predidx);
			} else {
				SendEvent(filter->event, 4, filter->description->Ref(), ev, predidx, valval->Ref());
			}
		}
	} 


	return filter->num_val_fields + filter->num_idx_fields;	
}


void Manager::EndCurrentSend(ReaderFrontend* reader) {
	Filter *i = FindFilter(reader);
	if ( i == 0 ) {
		reporter->InternalError("Unknown reader in EndCurrentSend");
		return;
	}

#ifdef DEBUG
		DBG_LOG(DBG_INPUT, "Got EndCurrentSend stream %s",
			i->name.c_str());
#endif

	if ( i->filter_type == EVENT_FILTER ) {
		// nothing to do..
		return;
	}

	assert(i->filter_type == TABLE_FILTER);
	TableFilter* filter = (TableFilter*) i;

	// lastdict contains all deleted entries and should be empty apart from that
	IterCookie *c = filter->lastDict->InitForIteration();
	filter->lastDict->MakeRobustCookie(c);
	InputHash* ih;
	HashKey *lastDictIdxKey;
	//while ( ( ih = i->lastDict->NextEntry(c) ) ) {
	while ( ( ih = filter->lastDict->NextEntry(lastDictIdxKey, c) ) ) {

		ListVal * idx = 0;
		Val *val = 0;
		
		Val* predidx = 0;
		EnumVal* ev = 0;
		int startpos = 0;

		if ( filter->pred || filter->event ) {
			idx = filter->tab->RecoverIndex(ih->idxkey);
			assert(idx != 0);
			val = filter->tab->Lookup(idx);
			assert(val != 0);
			predidx = ListValToRecordVal(idx, filter->itype, &startpos);
			ev = new EnumVal(BifEnum::Input::EVENT_REMOVED, BifType::Enum::Input::Event);
		}

		if ( filter->pred ) {
			// ask predicate, if we want to expire this element...

			Ref(ev);
			Ref(predidx);
			Ref(val);

			bool result = CallPred(filter->pred, 3, ev, predidx, val);

			if ( result == false ) {
				// Keep it. Hence - we quit and simply go to the next entry of lastDict
				// ah well - and we have to add the entry to currDict...
				Unref(predidx);
				Unref(ev);
				filter->currDict->Insert(lastDictIdxKey, filter->lastDict->RemoveEntry(lastDictIdxKey));
				continue;
			} 
		} 

		if ( filter->event ) {
			Ref(predidx);
			Ref(val);
			Ref(ev);
			SendEvent(filter->event, 3, ev, predidx, val);
		}

		if ( predidx )  // if we have a filter or an event...
			Unref(predidx);
		if ( ev ) 
			Unref(ev);

		filter->tab->Delete(ih->idxkey);
		filter->lastDict->Remove(lastDictIdxKey); // deletex in next line
		delete(ih);
	}

	filter->lastDict->Clear(); // should be empty->->-> but->->-> well->->-> who knows->->->
	delete(filter->lastDict);

	filter->lastDict = filter->currDict;	
	filter->currDict = new PDict(InputHash);

#ifdef DEBUG
		DBG_LOG(DBG_INPUT, "EndCurrentSend complete for  stream %s, queueing update_finished event",
			i->name.c_str());
#endif

	// Send event that the current update is indeed finished.
	EventHandler* handler = event_registry->Lookup("Input::update_finished");
	if ( handler == 0 ) {
		reporter->InternalError("Input::update_finished not found!");
	}	


	SendEvent(handler, 2, new StringVal(i->name.c_str()), new StringVal(i->source.c_str()));
}

void Manager::Put(ReaderFrontend* reader, Value* *vals) {
	Filter *i = FindFilter(reader);
	if ( i == 0 ) {
		reporter->InternalError("Unknown reader in Put");
		return;
	}

	int readFields;
	if ( i->filter_type == TABLE_FILTER ) {
		readFields = PutTable(i, vals);
	} else if ( i->filter_type == EVENT_FILTER ) {
		EnumVal *type = new EnumVal(BifEnum::Input::EVENT_NEW, BifType::Enum::Input::Event);
		readFields = SendEventFilterEvent(i, type, vals);
	} else {
		assert(false);
	}
	
	for ( int i = 0; i < readFields; i++ ) {
		delete vals[i];
	}
	delete [] vals;	

}

int Manager::SendEventFilterEvent(Filter* i, EnumVal* type, const Value* const *vals) {
	assert(i);

	assert(i->filter_type == EVENT_FILTER);
	EventFilter* filter = (EventFilter*) i;

	Val *val;
	list<Val*> out_vals;
	Ref(filter->description);
	out_vals.push_back(filter->description);
	// no tracking, send everything with a new event...
	//out_vals.push_back(new EnumVal(BifEnum::Input::EVENT_NEW, BifType::Enum::Input::Event));
	out_vals.push_back(type);

	int position = 0;
	if ( filter->want_record ) {
		RecordVal * r = ValueToRecordVal(vals, filter->fields, &position);
		out_vals.push_back(r);
	} else {
		for ( int j = 0; j < filter->fields->NumFields(); j++) {
			Val* val = 0;
			if ( filter->fields->FieldType(j)->Tag() == TYPE_RECORD ) {
				val = ValueToRecordVal(vals, filter->fields->FieldType(j)->AsRecordType(), &position);
			} else {
				val =  ValueToVal(vals[position], filter->fields->FieldType(j));
				position++;
			}
			out_vals.push_back(val);		
		}
	}

	SendEvent(filter->event, out_vals);

	return filter->fields->NumFields();

}

int Manager::PutTable(Filter* i, const Value* const *vals) {
	assert(i);

	assert(i->filter_type == TABLE_FILTER);
	TableFilter* filter = (TableFilter*) i;	

	Val* idxval = ValueToIndexVal(filter->num_idx_fields, filter->itype, vals);
	Val* valval;

	int position = filter->num_idx_fields;
	if ( filter->num_val_fields == 0 ) {
		valval = 0;
	} else if ( filter->num_val_fields == 1 && filter->want_record == 0 ) {
		valval = ValueToVal(vals[position], filter->rtype->FieldType(0));
	} else {
		valval = ValueToRecordVal(vals, filter->rtype, &position);
	}

	// if we have a subscribed event, we need to figure out, if this is an update or not
	// same for predicates
	if ( filter->pred || filter->event ) {
		bool updated = false;
		Val* oldval = 0;
		
		if ( filter->num_val_fields > 0 ) {
			// in that case, we need the old value to send the event (if we send an event).
			oldval = filter->tab->Lookup(idxval, false);
		}

		if ( oldval != 0 ) {
			// it is an update
			updated = true;
			Ref(oldval); // have to do that, otherwise it may disappear in assign
		}


		// predicate if we want the update or not
		if ( filter->pred ) {
			EnumVal* ev;
			int startpos = 0;
			Val* predidx = ValueToRecordVal(vals, filter->itype, &startpos);
			Ref(valval);

			if ( updated ) {
				ev = new EnumVal(BifEnum::Input::EVENT_CHANGED, BifType::Enum::Input::Event);
			} else {
				ev = new EnumVal(BifEnum::Input::EVENT_NEW, BifType::Enum::Input::Event);
			}
		
			bool result;
			if ( filter->num_val_fields > 0 ) { // we have values
				result = CallPred(filter->pred, 3, ev, predidx, valval);
			} else {
				// no values
				result = CallPred(filter->pred, 2, ev, predidx);
			}
			
			if ( result == false ) {
				// do nothing
				Unref(idxval);
				Unref(valval);
				Unref(oldval);
				return filter->num_val_fields + filter->num_idx_fields;
			}

		}

		filter->tab->Assign(idxval, valval);		

		if ( filter->event ) {	
			EnumVal* ev;
			int startpos = 0;
			Val* predidx = ValueToRecordVal(vals, filter->itype, &startpos);

			if ( updated ) { // in case of update send back the old value.
				assert ( filter->num_val_fields > 0 );
				ev = new EnumVal(BifEnum::Input::EVENT_CHANGED, BifType::Enum::Input::Event);
				assert ( oldval != 0 );
				SendEvent(filter->event, 4, filter->description->Ref(), ev, predidx, oldval);
			} else {
				ev = new EnumVal(BifEnum::Input::EVENT_NEW, BifType::Enum::Input::Event);
				if ( filter->num_val_fields == 0 ) {
					SendEvent(filter->event, 4, filter->description->Ref(), ev, predidx);
				} else {
					SendEvent(filter->event, 4, filter->description->Ref(), ev, predidx, valval->Ref());
				}
			}
		}


	} else {
		// no predicates or other stuff

		filter->tab->Assign(idxval, valval);
	}

	return filter->num_idx_fields + filter->num_val_fields;
}

// Todo:: perhaps throw some kind of clear-event?
void Manager::Clear(ReaderFrontend* reader) {
	Filter *i = FindFilter(reader);
	if ( i == 0 ) {
		reporter->InternalError("Unknown reader in Clear");
		return;
	}

#ifdef DEBUG
		DBG_LOG(DBG_INPUT, "Got Clear for stream %s",
			i->name.c_str());
#endif

	assert(i->filter_type == TABLE_FILTER);
	TableFilter* filter = (TableFilter*) i;	

	filter->tab->RemoveAll();
}

// put interface: delete old entry from table.
bool Manager::Delete(ReaderFrontend* reader, Value* *vals) {
	Filter *i = FindFilter(reader);
	if ( i == 0 ) {
		reporter->InternalError("Unknown reader in Delete");
		return false;
	}

	bool success = false;
	int readVals = 0;

	if ( i->filter_type == TABLE_FILTER ) {
		TableFilter* filter = (TableFilter*) i;		
		Val* idxval = ValueToIndexVal(filter->num_idx_fields, filter->itype, vals);
		assert(idxval != 0);
		readVals = filter->num_idx_fields + filter->num_val_fields;
		bool filterresult = true;

		if ( filter->pred || filter->event ) {
			Val *val = filter->tab->Lookup(idxval);

			if ( filter->pred ) {
				Ref(val);
				EnumVal *ev = new EnumVal(BifEnum::Input::EVENT_REMOVED, BifType::Enum::Input::Event);
				int startpos = 0;
				Val* predidx = ValueToRecordVal(vals, filter->itype, &startpos);

				filterresult = CallPred(filter->pred, 3, ev, predidx, val);

				if ( filterresult == false ) {
					// keep it.
					Unref(idxval);
					success = true;
				}

			}

			// only if filter = true -> no filtering
			if ( filterresult && filter->event ) {
				Ref(idxval);
				assert(val != 0);
				Ref(val); 
				EnumVal *ev = new EnumVal(BifEnum::Input::EVENT_REMOVED, BifType::Enum::Input::Event);
				SendEvent(filter->event, 4, filter->description->Ref(), ev, idxval, val);
			}
		}

		// only if filter = true -> no filtering
		if ( filterresult ) {
			success = ( filter->tab->Delete(idxval) != 0 );
			if ( !success ) {
				reporter->Error("Internal error while deleting values from input table");
			}
		}
	} else if ( i->filter_type == EVENT_FILTER  ) {
		EnumVal *type = new EnumVal(BifEnum::Input::EVENT_REMOVED, BifType::Enum::Input::Event);
		readVals = SendEventFilterEvent(i, type, vals);		
		success = true;
	} else {
		assert(false);
		return false;
	}

	for ( int i = 0; i < readVals; i++ ) {
		delete vals[i];
	}
	delete [] vals;		

	return success;
} 

bool Manager::CallPred(Func* pred_func, const int numvals, ...) 
{
	bool result;
	val_list vl(numvals);
	
	va_list lP;
	va_start(lP, numvals);
	for ( int i = 0; i < numvals; i++ ) 
	{
		vl.append( va_arg(lP, Val*) );
	}
	va_end(lP);

	Val* v = pred_func->Call(&vl);
	result = v->AsBool();
	Unref(v);

	return(result);
}

bool Manager::SendEvent(const string& name, const int num_vals, Value* *vals) 
{
	EventHandler* handler = event_registry->Lookup(name.c_str());
	if ( handler == 0 ) {
		reporter->Error("Event %s not found", name.c_str());
		return false;
	}

	RecordType *type = handler->FType()->Args();
	int num_event_vals = type->NumFields();
	if ( num_vals != num_event_vals ) {
		reporter->Error("Wrong number of values for event %s", name.c_str());
		return false;
	}

	val_list* vl = new val_list;
	for ( int i = 0; i < num_vals; i++) {
		vl->append(ValueToVal(vals[i], type->FieldType(i)));
	}

	mgr.Dispatch(new Event(handler, vl));

	for ( int i = 0; i < num_vals; i++ ) {
		delete vals[i];
	}
	delete [] vals;			

	return true;
} 

void Manager::SendEvent(EventHandlerPtr ev, const int numvals, ...) 
{
	val_list* vl = new val_list;
	
	va_list lP;
	va_start(lP, numvals);
	for ( int i = 0; i < numvals; i++ ) 
	{
		vl->append( va_arg(lP, Val*) );
	}
	va_end(lP);

	mgr.QueueEvent(ev, vl, SOURCE_LOCAL);
}

void Manager::SendEvent(EventHandlerPtr ev, list<Val*> events)
{
	val_list* vl = new val_list;
	
	for ( list<Val*>::iterator i = events.begin(); i != events.end(); i++ ) {
		vl->append( *i );
	}

	mgr.QueueEvent(ev, vl, SOURCE_LOCAL);
}

// Convert a bro list value to a bro record value. I / we could think about moving this functionality to val.cc
RecordVal* Manager::ListValToRecordVal(ListVal* list, RecordType *request_type, int* position) {
	assert(position != 0 ); // we need the pointer to point to data;

	if ( request_type->Tag() != TYPE_RECORD ) {
		reporter->InternalError("ListValToRecordVal called on non-record-value.");
		return 0;
	} 

	RecordVal* rec = new RecordVal(request_type->AsRecordType());

	assert(list != 0);
	int maxpos = list->Length();

	for ( int i = 0; i < request_type->NumFields(); i++ ) {
		assert ( (*position) <= maxpos );

		Val* fieldVal = 0;
		if ( request_type->FieldType(i)->Tag() == TYPE_RECORD ) {
			fieldVal = ListValToRecordVal(list, request_type->FieldType(i)->AsRecordType(), position);	
		} else {
			fieldVal = list->Index(*position);
			(*position)++;
		}

		rec->Assign(i, fieldVal);
	}

	return rec;
}

// Convert a threading value to a record value
RecordVal* Manager::ValueToRecordVal(const Value* const *vals, RecordType *request_type, int* position) {
	assert(position != 0); // we need the pointer to point to data.

	if ( request_type->Tag() != TYPE_RECORD ) {
		reporter->InternalError("ValueToRecordVal called on non-record-value.");
		return 0;
	} 

	RecordVal* rec = new RecordVal(request_type->AsRecordType());
	for ( int i = 0; i < request_type->NumFields(); i++ ) {

		Val* fieldVal = 0;
		if ( request_type->FieldType(i)->Tag() == TYPE_RECORD ) {
			fieldVal = ValueToRecordVal(vals, request_type->FieldType(i)->AsRecordType(), position);	
		} else {
			fieldVal = ValueToVal(vals[*position], request_type->FieldType(i));
			(*position)++;
		}

		rec->Assign(i, fieldVal);
	}

	return rec;
} 

// Count the length of the values
// used to create a correct length buffer for hashing later
int Manager::GetValueLength(const Value* val) {
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
		length += val->val.string_val->size();
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
				length += sizeof(val->val.subnet_val.prefix.in.in4)+sizeof(val->val.subnet_val.length);
				break;
			case IPv6:
				length += sizeof(val->val.subnet_val.prefix.in.in6)+sizeof(val->val.subnet_val.length);
				break;
			default:
				assert(false);
			}

		}
		break;

	case TYPE_TABLE: {
		for ( int i = 0; i < val->val.set_val.size; i++ ) {
			length += GetValueLength(val->val.set_val.vals[i]);
		}
		break;
		}

	case TYPE_VECTOR: {
		int j = val->val.vector_val.size;
		for ( int i = 0; i < j; i++ ) {
			length += GetValueLength(val->val.vector_val.vals[i]);
		}
		break;
		}

	default:
		reporter->InternalError("unsupported type %d for GetValueLength", val->type);
	}

	return length;
	
}

// Given a threading::value, copy the raw data bytes into *data and return how many bytes were copied.
// Used for hashing the values for lookup in the bro table
int Manager::CopyValue(char *data, const int startpos, const Value* val) {
	assert( val->present ); // presence has to be checked elsewhere

	switch ( val->type ) {
	case TYPE_BOOL:
	case TYPE_INT:
		memcpy(data+startpos, (const void*) &(val->val.int_val), sizeof(val->val.int_val));
		return sizeof(val->val.int_val);
		break;

	case TYPE_COUNT:
	case TYPE_COUNTER:
		memcpy(data+startpos, (const void*) &(val->val.uint_val), sizeof(val->val.uint_val));
		return sizeof(val->val.uint_val);
		break;

	case TYPE_PORT: {
		int length = 0;
		memcpy(data+startpos, (const void*) &(val->val.port_val.port), sizeof(val->val.port_val.port));
		length += sizeof(val->val.port_val.port);
		memcpy(data+startpos+length, (const void*) &(val->val.port_val.proto), sizeof(val->val.port_val.proto));
		length += sizeof(val->val.port_val.proto);
		return length;
		break;
		}
		

	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
		memcpy(data+startpos, (const void*) &(val->val.double_val), sizeof(val->val.double_val));
		return sizeof(val->val.double_val);
		break;

	case TYPE_STRING:
	case TYPE_ENUM:
		{
		memcpy(data+startpos, val->val.string_val->c_str(), val->val.string_val->length());
		return val->val.string_val->size();
		break;
		}

	case TYPE_ADDR:
		{
			int length;
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
		break;
	
	case TYPE_SUBNET: 
		{
			int length;
			switch ( val->val.subnet_val.prefix.family ) {
			case IPv4:
				length = sizeof(val->val.addr_val.in.in4);
				memcpy(data + startpos, (const char*) &(val->val.subnet_val.prefix.in.in4), length);
				break;
			case IPv6:
				length = sizeof(val->val.addr_val.in.in6);
				memcpy(data + startpos, (const char*) &(val->val.subnet_val.prefix.in.in4), length);
				break;
			default:
				assert(false);
			}
			int lengthlength = sizeof(val->val.subnet_val.length);
			memcpy(data + startpos + length , (const char*) &(val->val.subnet_val.length), lengthlength);
			length += lengthlength;
			return length;

		}
		break;

	case TYPE_TABLE: {
		int length = 0;
		int j = val->val.set_val.size;
		for ( int i = 0; i < j; i++ ) {
			length += CopyValue(data, startpos+length, val->val.set_val.vals[i]);
		}
		return length;
		break;				 
		}

	case TYPE_VECTOR: {
		int length = 0;
		int j = val->val.vector_val.size;
		for ( int i = 0; i < j; i++ ) {
			length += CopyValue(data, startpos+length, val->val.vector_val.vals[i]);
		}
		return length;
		break;				 
		}

	default:
		reporter->InternalError("unsupported type %d for CopyValue", val->type);
		return 0;
	}
	
	assert(false);
	return 0;
}

// Hash num_elements threading values and return the HashKey for them. At least one of the vals has to be ->present.
HashKey* Manager::HashValues(const int num_elements, const Value* const *vals) {
	int length = 0;

	for ( int i = 0; i < num_elements; i++ ) {
		const Value* val = vals[i];
		if ( val->present )
			length += GetValueLength(val);
	}

	if ( length == 0 ) {
		reporter->Error("Input reader sent line where all elements are null values. Ignoring line");
		return NULL;
	}

	int position = 0;
	char *data = (char*) malloc(length);
	if ( data == 0 ) {
		reporter->InternalError("Could not malloc?");
	}
	for ( int i = 0; i < num_elements; i++ ) {
		const Value* val = vals[i];
		if ( val->present )
			position += CopyValue(data, position, val);
	}

	HashKey *key = new HashKey(data, length);
	delete data;

	assert(position == length);
	return key;
}

// convert threading value to Bro value
Val* Manager::ValueToVal(const Value* val, BroType* request_type) {
	
	if ( request_type->Tag() != TYPE_ANY && request_type->Tag() != val->type ) {
		reporter->InternalError("Typetags don't match: %d vs %d", request_type->Tag(), val->type);
		return 0;
	}

	if ( !val->present ) {
		return 0; // unset field
	}

	switch ( val->type ) {
	case TYPE_BOOL:
	case TYPE_INT:
		return new Val(val->val.int_val, val->type);
		break;

	case TYPE_COUNT:
	case TYPE_COUNTER:
		return new Val(val->val.uint_val, val->type);
		break;
	
	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
		return new Val(val->val.double_val, val->type);
		break;

	case TYPE_STRING:
		{
		BroString *s = new BroString(*(val->val.string_val));
		return new StringVal(s);
		break;
		}
	
	case TYPE_PORT:
		return new PortVal(val->val.port_val.port, val->val.port_val.proto);
		break;

	case TYPE_ADDR:
		{
			IPAddr* addr;
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
			IPAddr* addr;
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
		break;

	case TYPE_TABLE: {
		// all entries have to have the same type...
		BroType* type = request_type->AsTableType()->Indices()->PureType();
		TypeList* set_index = new TypeList(type->Ref());
		set_index->Append(type->Ref());
		SetType* s = new SetType(set_index, 0);
		TableVal* t = new TableVal(s);
		for ( int i = 0; i < val->val.set_val.size; i++ ) {
			t->Assign(ValueToVal( val->val.set_val.vals[i], type ), 0);
		}
		return t;
		break;
		}

	case TYPE_VECTOR: {
		// all entries have to have the same type...
		BroType* type = request_type->AsVectorType()->YieldType();
		VectorType* vt = new VectorType(type->Ref());
		VectorVal* v = new VectorVal(vt);
		for (  int i = 0; i < val->val.vector_val.size; i++ ) {
			v->Assign(i, ValueToVal( val->val.set_val.vals[i], type ), 0);
		}
		return v;

		}

	case TYPE_ENUM: {
		// well, this is kind of stupid, because EnumType just mangles the module name and the var name together again...
		// but well
		string module = extract_module_name(val->val.string_val->c_str());
		string var = extract_var_name(val->val.string_val->c_str());
		bro_int_t index = request_type->AsEnumType()->Lookup(module, var.c_str());
		if ( index == -1 ) {
			reporter->InternalError("Value not found in enum mappimg. Module: %s, var: %s", module.c_str(), var.c_str());
		}
		return new EnumVal(index, request_type->Ref()->AsEnumType() );
		break;
		}
		

	default:
		reporter->InternalError("unsupported type for input_read");
	}

	assert(false);
	return NULL;
}
		
Manager::Filter* Manager::FindFilter(const string &name)
	{
	for ( map<ReaderFrontend*, Filter*>::iterator s = readers.begin(); s != readers.end(); ++s )
		{
		if ( (*s).second->name  == name ) 
		{
			return (*s).second;
		}
		}

	return 0;
	}

Manager::Filter* Manager::FindFilter(ReaderFrontend* reader) 
{
	map<ReaderFrontend*, Filter*>::iterator s = readers.find(reader);
	if ( s != readers.end() ) {
		return s->second;
	}
	return 0;
}
