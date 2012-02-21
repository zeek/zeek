// See the file "COPYING" in the main distribution directory for copyright.

#include <algorithm>

#include "Manager.h"
#include "ReaderFrontend.h"
#include "ReaderBackend.h"
#include "readers/Ascii.h"

#include "Event.h"
#include "EventHandler.h"
#include "NetVar.h"
#include "Net.h"


#include "CompHash.h"

#include "../threading/SerializationTypes.h"

using namespace input;
using threading::Value;
using threading::Field;

struct InputHash {
	hash_t valhash;
	HashKey* idxkey; // does not need ref or whatever - if it is present here, it is also still present in the TableVal.
};

declare(PDict, InputHash);

class Manager::Filter {
public:
	EnumVal* id;	
	string name;

	FilterType filter_type; // to distinguish between event and table filters

	virtual ~Filter();
};

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
};

Manager::TableFilter::TableFilter() {
	filter_type = TABLE_FILTER;
	
	tab = 0;
	itype = 0;
	rtype = 0;
}

Manager::EventFilter::EventFilter() {
	filter_type = EVENT_FILTER;
}

Manager::Filter::~Filter() {
	Unref(id);
}

Manager::TableFilter::~TableFilter() {
	Unref(tab);
	Unref(itype);
	if ( rtype ) // can be 0 for sets
		Unref(rtype);

	delete currDict;
	delete lastDict;
} 

struct Manager::ReaderInfo {
	EnumVal* id;
	EnumVal* type;
	ReaderFrontend* reader;

	//list<string> events; // events we fire when "something" happens
	map<int, Manager::Filter*> filters; // filters that can prevent our actions

	bool HasFilter(int id);	

	~ReaderInfo();
	};

Manager::ReaderInfo::~ReaderInfo() {
	map<int, Manager::Filter*>::iterator it = filters.begin();

	while ( it != filters.end() ) {
		delete (*it).second; 
		++it;
	}

	Unref(type);
	Unref(id);

	delete(reader);	
}

bool Manager::ReaderInfo::HasFilter(int id) {
	map<int, Manager::Filter*>::iterator it = filters.find(id);	
	if ( it == filters.end() ) {
		return false;
	}
	return true;
}


struct ReaderDefinition {
	bro_int_t type; // the type
	const char *name; // descriptive name for error messages
	bool (*init)(); // optional one-time inifializing function
	ReaderBackend* (*factory)(ReaderFrontend* frontend);	// factory function for creating instances
};

ReaderDefinition input_readers[] = {
	{ BifEnum::Input::READER_ASCII, "Ascii", 0, reader::Ascii::Instantiate },
	
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
			reporter->Error("unknown reader when creating reader");
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
					DBG_LOG(DBG_LOGGING, "failed to init input class %s", ir->name);
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
ReaderFrontend* Manager::CreateStream(EnumVal* id, RecordVal* description) 
{
	ReaderDefinition* ir = input_readers;
	
	RecordType* rtype = description->Type()->AsRecordType();
	if ( ! same_type(rtype, BifType::Record::Input::StreamDescription, 0) )
	{
		reporter->Error("Streamdescription argument not of right type");
		return 0;
	}

	EnumVal* reader = description->LookupWithDefault(rtype->FieldOffset("reader"))->AsEnumVal();
	EnumVal* mode = description->LookupWithDefault(rtype->FieldOffset("mode"))->AsEnumVal();
	Val *autostart = description->LookupWithDefault(rtype->FieldOffset("autostart"));	
	bool do_autostart = ( autostart->InternalInt() == 1 );
	Unref(autostart); // Ref'd by LookupWithDefault
	
	ReaderFrontend* reader_obj = new ReaderFrontend(reader->InternalInt());
	assert(reader_obj);
	
	// get the source...
	const BroString* bsource = description->Lookup(rtype->FieldOffset("source"))->AsString();
	string source((const char*) bsource->Bytes(), bsource->Len());

	ReaderInfo* info = new ReaderInfo;
	info->reader = reader_obj;
	info->type = reader->AsEnumVal(); // ref'd by lookupwithdefault
	info->id = id->Ref()->AsEnumVal();

	readers.push_back(info);

	reader_obj->Init(source, mode->InternalInt(), do_autostart);
	
	return reader_obj;
	
}

bool Manager::AddEventFilter(EnumVal *id, RecordVal* fval) {
	ReaderInfo *i = FindReader(id);
	if ( i == 0 ) {
		reporter->Error("Stream not found");
		return false;
	}

	RecordType* rtype = fval->Type()->AsRecordType();
	if ( ! same_type(rtype, BifType::Record::Input::EventFilter, 0) )
	{
		reporter->Error("filter argument not of right type");
		return false;
	}

	Val* name = fval->Lookup(rtype->FieldOffset("name"));
	RecordType *fields = fval->Lookup(rtype->FieldOffset("fields"))->AsType()->AsTypeType()->Type()->AsRecordType();	
	
	Val *want_record = fval->LookupWithDefault(rtype->FieldOffset("want_record"));	

	Val* event_val = fval->Lookup(rtype->FieldOffset("ev"));
	Func* event = event_val->AsFunc();

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

		if ( ! same_type((*args)[0], BifType::Enum::Input::Event, 0) ) 
		{
			reporter->Error("events first attribute must be of type Input::Event");
			return false;
		} 				

		if ( want_record->InternalInt() == 0 ) {
			if ( args->length() != fields->NumFields() + 1 ) {
				reporter->Error("events has wrong number of arguments");
				return false;
			}

			for ( int i = 0; i < fields->NumFields(); i++ ) {
				if ( !same_type((*args)[i+1], fields->FieldType(i) ) ) {
					reporter->Error("Incompatible type for event");
					return false;
				}
			}

		} else if ( want_record->InternalInt() == 1 ) {
			if ( args->length() != 2 ) {
				reporter->Error("events has wrong number of arguments");
				return false;
			}

			if ( !same_type((*args)[1], fields ) ) {
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

	EventFilter* filter = new EventFilter();
	filter->name = name->AsString()->CheckString();
	filter->id = id->Ref()->AsEnumVal();
	filter->num_fields = fieldsV.size();
	filter->fields = fields->Ref()->AsRecordType();
	filter->event = event_registry->Lookup(event->GetID()->Name());
	filter->want_record = ( want_record->InternalInt() == 1 );
	Unref(want_record); // ref'd by lookupwithdefault

	int filterid = 0;
	if ( i->filters.size() > 0 ) {
		filterid = i->filters.rbegin()->first + 1; // largest element is at beginning of map-> new id = old id + 1->
	}
	i->filters[filterid] = filter;
	i->reader->AddFilter( filterid, fieldsV.size(), logf );

	return true;
}

bool Manager::AddTableFilter(EnumVal *id, RecordVal* fval) {
	ReaderInfo *i = FindReader(id);
	if ( i == 0 ) {
		reporter->Error("Stream not found");
		return false;
	}

	RecordType* rtype = fval->Type()->AsRecordType();
	if ( ! same_type(rtype, BifType::Record::Input::TableFilter, 0) )
	{
		reporter->Error("filter argument not of right type");
		return false;
	}


	Val* name = fval->Lookup(rtype->FieldOffset("name"));
	Val* pred = fval->Lookup(rtype->FieldOffset("pred"));

	RecordType *idx = fval->Lookup(rtype->FieldOffset("idx"))->AsType()->AsTypeType()->Type()->AsRecordType();
	RecordType *val = 0;
	if ( fval->Lookup(rtype->FieldOffset("val")) != 0 ) {
		val = fval->Lookup(rtype->FieldOffset("val"))->AsType()->AsTypeType()->Type()->AsRecordType();
	}
	TableVal *dst = fval->Lookup(rtype->FieldOffset("destination"))->AsTableVal();

	Val *want_record = fval->LookupWithDefault(rtype->FieldOffset("want_record"));

	Val* event_val = fval->Lookup(rtype->FieldOffset("ev"));
	Func* event = event_val ? event_val->AsFunc() : 0;
	
	if ( event ) {
		FuncType* etype = event->FType()->AsFuncType();
		
		if ( ! etype->IsEvent() ) {
			reporter->Error("stream event is a function, not an event");
			return false;
		}

		const type_list* args = etype->ArgTypes()->Types();

		if ( args->length() != 3 ) 
		{
			reporter->Error("Table event must take 3 arguments");
			return false;
		}

		if ( ! same_type((*args)[0], BifType::Enum::Input::Event, 0) ) 
		{
			reporter->Error("table events first attribute must be of type Input::Event");
			return false;
		} 		

		if ( ! same_type((*args)[1], idx) ) 
		{
			reporter->Error("table events index attributes do not match");
			return false;
		} 
		
		if ( want_record->InternalInt() == 1 && ! same_type((*args)[2], val) ) 
		{
			reporter->Error("table events value attributes do not match");
			return false;
		} else if (  want_record->InternalInt() == 0 && !same_type((*args)[2], val->FieldType(0) ) ) {
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
	
	TableFilter* filter = new TableFilter();
	filter->name = name->AsString()->CheckString();
	filter->id = id->Ref()->AsEnumVal();
	filter->pred = pred ? pred->AsFunc() : 0;
	filter->num_idx_fields = idxfields;
	filter->num_val_fields = valfields;
	filter->tab = dst->Ref()->AsTableVal();
	filter->rtype = val ? val->Ref()->AsRecordType() : 0;
	filter->itype = idx->Ref()->AsRecordType();
	filter->event = event ? event_registry->Lookup(event->GetID()->Name()) : 0;
	filter->currDict = new PDict(InputHash);
	filter->lastDict = new PDict(InputHash);
	filter->want_record = ( want_record->InternalInt() == 1 );
	Unref(want_record); // ref'd by lookupwithdefault

	if ( valfields > 1 ) {
		assert(filter->want_record);
	}
	
	int filterid = 0;
	if ( i->filters.size() > 0 ) {
		filterid = i->filters.rbegin()->first + 1; // largest element is at beginning of map-> new id = old id + 1->
	}
	i->filters[filterid] = filter;
	i->reader->AddFilter( filterid, fieldsV.size(), fields );

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


bool Manager::RemoveStream(const EnumVal* id) {
	ReaderInfo *i = 0;
	for ( vector<ReaderInfo *>::iterator s = readers.begin(); s != readers.end(); ++s )
		{
			if ( (*s)->id == id ) 
			{
				i = (*s);
				break;	
			}
		}

	if ( i == 0 ) {
		return false; // not found
	}

	i->reader->Finish();

	return true;
}

bool Manager::RemoveStreamContinuation(const ReaderFrontend* reader) {
	ReaderInfo *i = 0;


	for ( vector<ReaderInfo *>::iterator s = readers.begin(); s != readers.end(); ++s )
	{
		if ( (*s)->reader && (*s)->reader == reader ) 
		{
			i = *s;
			delete(i);
			readers.erase(s);
			return true;
		}
	}
	
	reporter->Error("Stream not found in RemoveStreamContinuation");
	return false;

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

			fields->push_back(field);
		}
	}

	return true;
}

bool Manager::ForceUpdate(const EnumVal* id)
{
	ReaderInfo *i = FindReader(id);
	if ( i == 0 ) {
		reporter->Error("Reader not found");
		return false;
	}
 
	i->reader->Update();

	return true; // update is async :(
}

bool Manager::RemoveTableFilter(EnumVal* id, const string &name) {
	ReaderInfo *i = FindReader(id);
	if ( i == 0 ) {
		reporter->Error("Reader not found");
		return false;
	}

	bool found = false;
	int filterId;

	for ( map<int, Manager::Filter*>::iterator it = i->filters.begin(); it != i->filters.end(); ++it ) {
		if ( (*it).second->name == name ) {
			found = true;
			filterId = (*it).first;

			if ( (*it).second->filter_type != TABLE_FILTER ) {
				reporter->Error("Trying to remove filter %s of wrong type", name.c_str());
				return false;
			}

			break;
		}
	}

	if ( !found ) {
		reporter->Error("Trying to remove nonexisting filter %s", name.c_str());
		return false;
	}

	i->reader->RemoveFilter(filterId);

	return true;
}

bool Manager::RemoveFilterContinuation(const ReaderFrontend* reader, const int filterId) {
	ReaderInfo *i = FindReader(reader);
	if ( i == 0 ) {
		reporter->Error("Reader not found");
		return false;
	}

	map<int, Manager::Filter*>::iterator it = i->filters.find(filterId);
	if ( it == i->filters.end() ) {
		reporter->Error("Got RemoveFilterContinuation where filter nonexistant for %d", filterId);
		return false;
	}

	delete (*it).second;
	i->filters.erase(it);

	return true;
} 

bool Manager::RemoveEventFilter(EnumVal* id, const string &name) {
	ReaderInfo *i = FindReader(id);
	if ( i == 0 ) {
		reporter->Error("Reader not found");
		return false;
	}

	bool found = false;
	int filterId;
	for ( map<int, Manager::Filter*>::iterator it = i->filters.begin(); it != i->filters.end(); ++it ) {
		if ( (*it).second->name == name ) {
			found = true;
			filterId = (*it).first;

			if ( (*it).second->filter_type != EVENT_FILTER ) {
				reporter->Error("Trying to remove filter %s of wrong type", name.c_str());
				return false;
			}

			break;
		}
	}
	
	if ( !found ) {
		reporter->Error("Trying to remove nonexisting filter %s", name.c_str());
		return false;
	}

	i->reader->RemoveFilter(filterId);
	return true;
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

	//reporter->Error("Position: %d, num_fields: %d", position, num_fields);
	assert ( position == num_fields );

	return idxval;
}


void Manager::SendEntry(const ReaderFrontend* reader, const int id, Value* *vals) {
	ReaderInfo *i = FindReader(reader);
	if ( i == 0 ) {
		reporter->InternalError("Unknown reader");
		return;
	}

	if ( !i->HasFilter(id) ) {
		reporter->InternalError("Unknown filter");
		return;
	}

	int readFields;
	if ( i->filters[id]->filter_type == TABLE_FILTER ) {
		readFields = SendEntryTable(reader, id, vals);
	} else if ( i->filters[id]->filter_type == EVENT_FILTER ) {
		EnumVal *type = new EnumVal(BifEnum::Input::EVENT_NEW, BifType::Enum::Input::Event);
		readFields = SendEventFilterEvent(reader, type, id, vals);		
	} else {
		assert(false);
	}

	for ( int i = 0; i < readFields; i++ ) {
		delete vals[i];
	}
	delete [] vals;	
	

}

int Manager::SendEntryTable(const ReaderFrontend* reader, const int id, const Value* const *vals) {
	ReaderInfo *i = FindReader(reader);

	bool updated = false;

	assert(i);
	assert(i->HasFilter(id));

	assert(i->filters[id]->filter_type == TABLE_FILTER);
	TableFilter* filter = (TableFilter*) i->filters[id];

	//reporter->Error("Hashing %d index fields", i->num_idx_fields);
	HashKey* idxhash = HashValues(filter->num_idx_fields, vals);
	//reporter->Error("Result: %d\n", (uint64_t) idxhash->Hash());
	//reporter->Error("Hashing %d val fields", i->num_val_fields);
	
	hash_t valhash = 0;
	if ( filter->num_val_fields > 0 ) {
		HashKey* valhashkey = HashValues(filter->num_val_fields, vals+filter->num_idx_fields);
	     	valhash = valhashkey->Hash();
	      	delete(valhashkey);
	}

	//reporter->Error("Result: %d", (uint64_t) valhash->Hash());
	
	//reporter->Error("received entry with idxhash %d and valhash %d", (uint64_t) idxhash->Hash(), (uint64_t) valhash->Hash());

	InputHash *h = filter->lastDict->Lookup(idxhash);
	if ( h != 0 ) {
		// seen before
		if ( filter->num_val_fields == 0 || h->valhash == valhash ) {
			// ok, exact duplicate
			filter->lastDict->Remove(idxhash);
			filter->currDict->Insert(idxhash, h);
			return filter->num_val_fields + filter->num_idx_fields;
		} else {
			assert( filter->num_val_fields > 0 );
			// updated
			filter->lastDict->Remove(idxhash);
			delete(h);
			updated = true;
			
		}
	}


	Val* idxval = ValueToIndexVal(filter->num_idx_fields, filter->itype, vals);
	Val* valval;
	
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
		Val* predidx = ValueToRecordVal(vals, filter->itype, &startpos);
		Ref(valval);

		if ( updated ) {
			ev = new EnumVal(BifEnum::Input::EVENT_CHANGED, BifType::Enum::Input::Event);
		} else {
			ev = new EnumVal(BifEnum::Input::EVENT_NEW, BifType::Enum::Input::Event);
		}
		
		val_list vl( 2 + (filter->num_val_fields > 0) ); // 2 if we don't have values, 3 otherwise.
		vl.append(ev);
		vl.append(predidx);
		if ( filter->num_val_fields > 0 )
			vl.append(valval);

		Val* v = filter->pred->Call(&vl);
		bool result = v->AsBool();
		Unref(v);

		if ( result == false ) {
			if ( !updated ) {
				// throw away. Hence - we quit. And remove the entry from the current dictionary...
				delete(filter->currDict->RemoveEntry(idxhash));
				return filter->num_val_fields + filter->num_idx_fields;
			} else {
				// keep old one
				filter->currDict->Insert(idxhash, h);
				return filter->num_val_fields + filter->num_idx_fields;
			}
		}

	}
	

	Val* oldval = 0;
	if ( updated == true ) {
		assert(filter->num_val_fields > 0);
		// in that case, we need the old value to send the event (if we send an event).
		oldval = filter->tab->Lookup(idxval, false);
	}

	//i->tab->Assign(idxval, valval);
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

	filter->currDict->Insert(idxhash, ih);

	if ( filter->event ) {
		EnumVal* ev;
		int startpos = 0;
		Val* predidx = ValueToRecordVal(vals, filter->itype, &startpos);

		if ( updated ) { // in case of update send back the old value.
			assert ( filter->num_val_fields > 0 );
			ev = new EnumVal(BifEnum::Input::EVENT_CHANGED, BifType::Enum::Input::Event);
			assert ( oldval != 0 );
			SendEvent(filter->event, 3, ev, predidx, oldval);
		} else {
			ev = new EnumVal(BifEnum::Input::EVENT_NEW, BifType::Enum::Input::Event);
			Ref(valval);
			if ( filter->num_val_fields == 0 ) {
				SendEvent(filter->event, 3, ev, predidx);
			} else {
				SendEvent(filter->event, 3, ev, predidx, valval);
			}
		}
	} 


	return filter->num_val_fields + filter->num_idx_fields;	
}


void Manager::EndCurrentSend(const ReaderFrontend* reader, int id) {
	ReaderInfo *i = FindReader(reader);
	if ( i == 0 ) {
		reporter->InternalError("Unknown reader");
		return;
	}

	assert(i->HasFilter(id));

	if ( i->filters[id]->filter_type == EVENT_FILTER ) {
		// nothing to do..
		return;
	}

	assert(i->filters[id]->filter_type == TABLE_FILTER);
	TableFilter* filter = (TableFilter*) i->filters[id];

	// lastdict contains all deleted entries and should be empty apart from that
	IterCookie *c = filter->lastDict->InitForIteration();
	filter->lastDict->MakeRobustCookie(c);
	InputHash* ih;
	HashKey *lastDictIdxKey;
	//while ( ( ih = i->lastDict->NextEntry(c) ) ) {
	while ( ( ih = filter->lastDict->NextEntry(lastDictIdxKey, c) ) ) {

		ListVal * idx = 0;
		Val *val = 0;

		if ( filter->pred || filter->event ) {
			idx = filter->tab->RecoverIndex(ih->idxkey);
			assert(idx != 0);
			val = filter->tab->Lookup(idx);
			assert(val != 0);
		}

		if ( filter->pred ) {

			bool doBreak = false;
			// ask predicate, if we want to expire this element...

			EnumVal* ev = new EnumVal(BifEnum::Input::EVENT_REMOVED, BifType::Enum::Input::Event);
			//Ref(idx);
			int startpos = 0;
			Val* predidx = ListValToRecordVal(idx, filter->itype, &startpos);
			Ref(val);

			val_list vl(3);
			vl.append(ev);
			vl.append(predidx);
			vl.append(val);
			Val* v = filter->pred->Call(&vl);
			bool result = v->AsBool();
			Unref(v);
			
			if ( result == false ) {
				// Keep it. Hence - we quit and simply go to the next entry of lastDict
				// ah well - and we have to add the entry to currDict...
				filter->currDict->Insert(lastDictIdxKey, filter->lastDict->RemoveEntry(lastDictIdxKey));
				continue;
			}


		}

		if ( filter->event ) {
			int startpos = 0;
			Val* predidx = ListValToRecordVal(idx, filter->itype, &startpos);
			Ref(val);
			EnumVal *ev = new EnumVal(BifEnum::Input::EVENT_REMOVED, BifType::Enum::Input::Event);
			SendEvent(filter->event, 3, ev, predidx, val);
		}

		filter->tab->Delete(ih->idxkey);
		filter->lastDict->Remove(lastDictIdxKey); // deletex in next line
		delete(ih);
	}

	filter->lastDict->Clear(); // should be empty->->-> but->->-> well->->-> who knows->->->
	delete(filter->lastDict);

	filter->lastDict = filter->currDict;	
	filter->currDict = new PDict(InputHash);

	// Send event that the current update is indeed finished.
	EventHandler* handler = event_registry->Lookup("Input::update_finished");
	if ( handler == 0 ) {
		reporter->InternalError("Input::update_finished not found!");
	}	


	Ref(i->id);
	SendEvent(handler, 1, i->id);
}

void Manager::Put(const ReaderFrontend* reader, int id, Value* *vals) {
	ReaderInfo *i = FindReader(reader);
	if ( i == 0 ) {
		reporter->InternalError("Unknown reader");
		return;
	}

	if ( !i->HasFilter(id) ) {
		reporter->InternalError("Unknown filter");
		return;
	}

	if ( i->filters[id]->filter_type == TABLE_FILTER ) {
		PutTable(reader, id, vals);
	} else if ( i->filters[id]->filter_type == EVENT_FILTER ) {
		EnumVal *type = new EnumVal(BifEnum::Input::EVENT_NEW, BifType::Enum::Input::Event);
		SendEventFilterEvent(reader, type, id, vals);
	} else {
		assert(false);
	}

}

int Manager::SendEventFilterEvent(const ReaderFrontend* reader, EnumVal* type, int id, const Value* const *vals) {
	ReaderInfo *i = FindReader(reader);

	bool updated = false;

	assert(i);
	assert(i->HasFilter(id));

	assert(i->filters[id]->filter_type == EVENT_FILTER);
	EventFilter* filter = (EventFilter*) i->filters[id];

	Val *val;
	list<Val*> out_vals;
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

int Manager::PutTable(const ReaderFrontend* reader, int id, const Value* const *vals) {
	ReaderInfo *i = FindReader(reader);

	assert(i);
	assert(i->HasFilter(id));

	assert(i->filters[id]->filter_type == TABLE_FILTER);
	TableFilter* filter = (TableFilter*) i->filters[id];	

	Val* idxval = ValueToIndexVal(filter->num_idx_fields, filter->itype, vals);
	Val* valval;

	
	int position = filter->num_idx_fields;
	if ( filter->num_val_fields == 0 ) {
		valval = 0;
	} else if ( filter->num_val_fields == 1 && !filter->want_record ) {
		valval = ValueToVal(vals[filter->num_idx_fields], filter->rtype->FieldType(filter->num_idx_fields));
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
			
			val_list vl( 2 + (filter->num_val_fields > 0) ); // 2 if we don't have values, 3 otherwise.
			vl.append(ev);
			vl.append(predidx);
			if ( filter->num_val_fields > 0 )
				vl.append(valval);

			Val* v = filter->pred->Call(&vl);
			bool result = v->AsBool();
			Unref(v);

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
				SendEvent(filter->event, 3, ev, predidx, oldval);
			} else {
				ev = new EnumVal(BifEnum::Input::EVENT_NEW, BifType::Enum::Input::Event);
				Ref(valval);
				if ( filter->num_val_fields == 0 ) {
					SendEvent(filter->event, 3, ev, predidx);
				} else {
					SendEvent(filter->event, 3, ev, predidx, valval);
				}
			}
			
		}





	} else {
		// no predicates or other stuff

		filter->tab->Assign(idxval, valval);
	}

	return filter->num_idx_fields + filter->num_val_fields;
}

void Manager::Clear(const ReaderFrontend* reader, int id) {
	ReaderInfo *i = FindReader(reader);
	if ( i == 0 ) {
		reporter->InternalError("Unknown reader");
		return;
	}

	assert(i->HasFilter(id));	

	assert(i->filters[id]->filter_type == TABLE_FILTER);
	TableFilter* filter = (TableFilter*) i->filters[id];	

	filter->tab->RemoveAll();
}

bool Manager::Delete(const ReaderFrontend* reader, int id, Value* *vals) {
	ReaderInfo *i = FindReader(reader);
	if ( i == 0 ) {
		reporter->InternalError("Unknown reader");
		return false;
	}

	assert(i->HasFilter(id));			

	bool success = false;
	int readVals = 0;

	if ( i->filters[id]->filter_type == TABLE_FILTER ) {
		TableFilter* filter = (TableFilter*) i->filters[id];		
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

				val_list vl(3);
				vl.append(ev);
				vl.append(predidx);
				vl.append(val);
				Val* v = filter->pred->Call(&vl);
				filterresult = v->AsBool();
				Unref(v);

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
				SendEvent(filter->event, 3, ev, idxval, val);
			}
		}

		// only if filter = true -> no filtering
		if ( filterresult ) {
			success = ( filter->tab->Delete(idxval) != 0 );
			if ( !success ) {
				reporter->Error("Internal error while deleting values from input table");
			}
		}
	} else if ( i->filters[id]->filter_type == EVENT_FILTER  ) {
		EnumVal *type = new EnumVal(BifEnum::Input::EVENT_REMOVED, BifType::Enum::Input::Event);
		readVals = SendEventFilterEvent(reader, type, id, vals);		
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


RecordVal* Manager::ListValToRecordVal(ListVal* list, RecordType *request_type, int* position) {
	RecordVal* rec = new RecordVal(request_type->AsRecordType());

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



RecordVal* Manager::ValueToRecordVal(const Value* const *vals, RecordType *request_type, int* position) {
	if ( position == 0 ) {
		reporter->InternalError("Need position");
		return 0;
	}

	/*
	if ( request_type->Tag() != TYPE_RECORD ) {
		reporter->InternalError("I only work with records");
		return 0;
	} */


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


int Manager::GetValueLength(const Value* val) {
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
		length += NUM_ADDR_WORDS*sizeof(uint32_t);
		break;

	case TYPE_SUBNET:
		length += sizeof(val->val.subnet_val.width);
		length += sizeof(val->val.subnet_val.net);
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

int Manager::CopyValue(char *data, const int startpos, const Value* val) {
	switch ( val->type ) {
	case TYPE_BOOL:
	case TYPE_INT:
		//reporter->Error("Adding field content to pos %d: %lld", val->val.int_val, startpos); 
		memcpy(data+startpos, (const void*) &(val->val.int_val), sizeof(val->val.int_val));
		//*(data+startpos) = val->val.int_val;
		return sizeof(val->val.int_val);
		break;

	case TYPE_COUNT:
	case TYPE_COUNTER:
		//*(data+startpos) = val->val.uint_val;
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
		//*(data+startpos) = val->val.double_val;
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
		memcpy(data+startpos, val->val.addr_val, NUM_ADDR_WORDS*sizeof(uint32_t));
		return NUM_ADDR_WORDS*sizeof(uint32_t);
		break;

	case TYPE_SUBNET: {
		int length = 0;
		memcpy(data+startpos,(const char*)  &(val->val.subnet_val.width), sizeof(val->val.subnet_val.width) );
		length += sizeof(val->val.subnet_val.width);
		memcpy(data+startpos+length, (const char*) &(val->val.subnet_val.net), sizeof(val->val.subnet_val.net) );
		length += sizeof(val->val.subnet_val.net);		
		return length;
		break;
		}

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
	
	reporter->InternalError("internal error");
	assert(false);
	return 0;

}

HashKey* Manager::HashValues(const int num_elements, const Value* const *vals) {
	int length = 0;

	for ( int i = 0; i < num_elements; i++ ) {
		const Value* val = vals[i];
		length += GetValueLength(val);
	}

	//reporter->Error("Length: %d", length);

	int position = 0;
	char *data = (char*) malloc(length);
	if ( data == 0 ) {
		reporter->InternalError("Could not malloc?");
	}
	//memset(data, 0, length);
	for ( int i = 0; i < num_elements; i++ ) {
		const Value* val = vals[i];
		position += CopyValue(data, position, val);
	}

	hash_t key = HashKey::HashBytes(data, length);

	assert(position == length);
	return new HashKey(data, length, key, true);


}

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
		return new AddrVal(val->val.addr_val);
		break;

	case TYPE_SUBNET:
		return new SubNetVal(val->val.subnet_val.net, val->val.subnet_val.width);
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


	reporter->InternalError("Impossible error");
	return NULL;
}
		
Manager::ReaderInfo* Manager::FindReader(const ReaderFrontend* reader)
	{
	for ( vector<ReaderInfo *>::iterator s = readers.begin(); s != readers.end(); ++s )
		{
		if ( (*s)->reader && (*s)->reader == reader ) 
		{
			return *s;
		}
		}

	return 0;
	}

		
Manager::ReaderInfo* Manager::FindReader(const EnumVal* id)
	{
	for ( vector<ReaderInfo *>::iterator s = readers.begin(); s != readers.end(); ++s )
		{
		if ( (*s)->id && (*s)->id->AsEnum() == id->AsEnum() ) 
		{
			return *s;
		}
		}

	return 0;
	}

