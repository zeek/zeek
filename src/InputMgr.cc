// See the file "COPYING" in the main distribution directory for copyright.

#include <algorithm>

#include "InputMgr.h"
#include "Event.h"
#include "EventHandler.h"
#include "NetVar.h"
#include "Net.h"


#include "InputReader.h"

#include "InputReaderAscii.h"

#include "CompHash.h"


struct InputHash {
	HashKey* valhash;
	HashKey* idxkey; // does not need ref or whatever - if it is present here, it is also still present in the TableVal.
};

declare(PDict, InputHash);

class InputMgr::Filter {
public:
	EnumVal* id;	
	string name;

	//int filter_type; // to distinguish between event and table filters

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
	RecordType* event_type;

	// ~Filter();
	// Filter();
	// Filter(const InputMgr::Filter& filter);
	
	void DoCleanup();
};

/* 
InputMgr::Filter::Filter() {
	tab = 0;
	itype = 0;
	rtype = 0;
	event_type = 0;
}

InputMgr::Filter::Filter(const InputMgr::Filter& f) {
	id = f.id;
	id->Ref();

	tab = f.tab;
	if ( tab ) 
		tab->Ref();

	itype = f.itype;
	if ( itype ) 
		itype->Ref();

	rtype = f.rtype;
	if ( rtype ) 
		Ref(rtype);

	event_type = f.event_type;
	if ( event_type ) 
		Ref(event_type);

	name = f.name;
	num_idx_fields = f.num_idx_fields;
	num_val_fields = f.num_val_fields;
	want_record = f.want_record;


} */

void InputMgr::Filter::DoCleanup() {
	Unref(id);
	if ( tab ) 
		Unref(tab);
	if ( itype ) 
		Unref(itype);
	if ( rtype )
		Unref(rtype);
	if ( event_type)
		Unref(event_type);

	delete currDict;
	delete lastDict;
} 

struct InputMgr::ReaderInfo {
	EnumVal* id;
	EnumVal* type;
	InputReader* reader;

	//list<string> events; // events we fire when "something" happens
	map<int, InputMgr::Filter> filters; // filters that can prevent our actions

	bool HasFilter(int id);	

	~ReaderInfo();
	};

InputMgr::ReaderInfo::~ReaderInfo() {
	// all the contents of filters should delete themselves automatically...

	Unref(type);
	Unref(id);

	delete(reader);	
}

bool InputMgr::ReaderInfo::HasFilter(int id) {
	map<int, InputMgr::Filter>::iterator it = filters.find(id);	
	if ( it == filters.end() ) {
		return false;
	}
	return true;
}


struct InputReaderDefinition {
	bro_int_t type; // the type
	const char *name; // descriptive name for error messages
	bool (*init)(); // optional one-time inifializing function
	InputReader* (*factory)();	// factory function for creating instances
};

InputReaderDefinition input_readers[] = {
	{ BifEnum::Input::READER_ASCII, "Ascii", 0, InputReaderAscii::Instantiate },
	
	// End marker
	{ BifEnum::Input::READER_DEFAULT, "None", 0, (InputReader* (*)())0 }
};

InputMgr::InputMgr()
{
}

// create a new input reader object to be used at whomevers leisure lateron.
InputReader* InputMgr::CreateStream(EnumVal* id, RecordVal* description) 
{
	InputReaderDefinition* ir = input_readers;
	
	RecordType* rtype = description->Type()->AsRecordType();
	if ( ! same_type(rtype, BifType::Record::Input::StreamDescription, 0) )
	{
		reporter->Error("Streamdescription argument not of right type");
		return 0;
	}

	EnumVal* reader = description->LookupWithDefault(rtype->FieldOffset("reader"))->AsEnumVal();
	
	while ( true ) {
		if ( ir->type == BifEnum::Input::READER_DEFAULT ) 
		{
			reporter->Error("unknown reader when creating reader");
			return 0;
		}

		if ( ir->type != reader->AsEnum() ) {
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
	InputReader* reader_obj = (*ir->factory)();
	assert(reader_obj);
	
	// get the source...
	const BroString* bsource = description->Lookup(rtype->FieldOffset("source"))->AsString();
	string source((const char*) bsource->Bytes(), bsource->Len());


	ReaderInfo* info = new ReaderInfo;
	info->reader = reader_obj;
	info->type = reader->AsEnumVal(); // ref'd by lookupwithdefault
	info->id = id->Ref()->AsEnumVal();

	readers.push_back(info);

	int success = reader_obj->Init(source);
	if ( success == false ) {
		assert( RemoveStream(id) );
		return 0;
	}
	success = reader_obj->Update();
	if ( success == false ) {
		assert ( RemoveStream(id) );
		return 0;
	}
	
	return reader_obj;
	
}

bool InputMgr::AddTableFilter(EnumVal *id, RecordVal* fval) {
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
	RecordType *val = fval->Lookup(rtype->FieldOffset("val"))->AsType()->AsTypeType()->Type()->AsRecordType();
	TableVal *dst = fval->Lookup(rtype->FieldOffset("destination"))->AsTableVal();

	vector<LogField*> fieldsV; // vector, because we don't know the length beforehands

	bool status = !UnrollRecordType(&fieldsV, idx, "");

	int idxfields = fieldsV.size();
	
	status = status || !UnrollRecordType(&fieldsV, val, "");
	int valfields = fieldsV.size() - idxfields;

	if ( status ) {
		reporter->Error("Problem unrolling");
		return false;
	}
	
	Val *want_record = fval->LookupWithDefault(rtype->FieldOffset("want_record"));
	
	LogField** fields = new LogField*[fieldsV.size()];
	for ( unsigned int i = 0; i < fieldsV.size(); i++ ) {
		fields[i] = fieldsV[i];
	}
	
	// FIXME: remove those funky 0-tests again as the idea was changed.
	Filter filter;
	filter.name = name->AsString()->CheckString();
	filter.id = id->Ref()->AsEnumVal();
	filter.pred = pred ? pred->AsFunc() : 0;
	filter.num_idx_fields = idxfields;
	filter.num_val_fields = valfields;
	filter.tab = dst ? dst->Ref()->AsTableVal() : 0;
	filter.rtype = val ? val->Ref()->AsRecordType() : 0;
	filter.itype = idx ? idx->Ref()->AsRecordType() : 0;
	// ya - well - we actually don't need them in every case... well, a few bytes of memory wasted
	filter.currDict = new PDict(InputHash);
	filter.lastDict = new PDict(InputHash);
	filter.want_record = ( want_record->InternalInt() == 1 );
	Unref(want_record); // ref'd by lookupwithdefault

	if ( valfields > 1 ) {
		assert(filter.want_record);
	}
	
	i->filters[id->InternalInt()] = filter;
	i->reader->AddFilter( id->InternalInt(), fieldsV.size(), fields );

	return true;
}


bool InputMgr::IsCompatibleType(BroType* t, bool atomic_only)
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


bool InputMgr::RemoveStream(const EnumVal* id) {
	ReaderInfo *i = 0;
	for ( vector<ReaderInfo *>::iterator s = readers.begin(); s != readers.end(); ++s )
		{
			if ( (*s)->id == id ) 
			{
				i = (*s);
				readers.erase(s); // remove from vector
				break;	
			}
		}

	if ( i == 0 ) {
		return false; // not found
	}

	i->reader->Finish();

	delete(i);

	return true;
}

bool InputMgr::UnrollRecordType(vector<LogField*> *fields, const RecordType *rec, const string& nameprepend) {
	for ( int i = 0; i < rec->NumFields(); i++ ) 
	{

		if ( !IsCompatibleType(rec->FieldType(i)) ) {
			reporter->Error("Incompatible type \"%s\" in table definition for InputReader", type_name(rec->FieldType(i)->Tag()));
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
			LogField* field = new LogField();
			field->name = nameprepend + rec->FieldName(i);
			field->type = rec->FieldType(i)->Tag();	
			if ( field->type == TYPE_TABLE ) {
				field->subtype = rec->FieldType(i)->AsSetType()->Indices()->PureType()->Tag();
			} else if ( field->type == TYPE_VECTOR ) {
				field->subtype = rec->FieldType(i)->AsVectorType()->YieldType()->Tag();
			}

			fields->push_back(field);
		}
	}

	return true;
}

bool InputMgr::ForceUpdate(const EnumVal* id)
{
	ReaderInfo *i = FindReader(id);
	if ( i == 0 ) {
		reporter->Error("Reader not found");
		return false;
	}
 
	return i->reader->Update();
}

bool InputMgr::RemoveTableFilter(EnumVal* id, const string &name) {
	ReaderInfo *i = FindReader(id);
	if ( i == 0 ) {
		reporter->Error("Reader not found");
		return false;
	}

	map<int, InputMgr::Filter>::iterator it = i->filters.find(id->InternalInt());
	if ( it == i->filters.end() ) {
		return false;
	}

	i->filters[id->InternalInt()].DoCleanup();

	i->filters.erase(it);
	return true;
}

Val* InputMgr::LogValToIndexVal(int num_fields, const RecordType *type, const LogVal* const *vals) {
	Val* idxval;
	int position = 0;


	if ( num_fields == 1 && type->FieldType(0)->Tag() != TYPE_RECORD  ) {
		idxval = LogValToVal(vals[0], type->FieldType(0));
		position = 1;
	} else {
		ListVal *l = new ListVal(TYPE_ANY);
		for ( int j = 0 ; j < type->NumFields(); j++ ) {
			if ( type->FieldType(j)->Tag() == TYPE_RECORD ) {
				l->Append(LogValToRecordVal(vals, type->FieldType(j)->AsRecordType(), &position));
			} else {
				l->Append(LogValToVal(vals[position], type->FieldType(j)));
				position++;
			}
		}
		idxval = l;
	}

	//reporter->Error("Position: %d, num_fields: %d", position, num_fields);
	assert ( position == num_fields );

	return idxval;
}


void InputMgr::SendEntry(const InputReader* reader, int id, const LogVal* const *vals) {
	ReaderInfo *i = FindReader(reader);
	if ( i == 0 ) {
		reporter->InternalError("Unknown reader");
		return;
	}

	bool updated = false;

	assert(i->HasFilter(id));

	//reporter->Error("Hashing %d index fields", i->num_idx_fields);
	HashKey* idxhash = HashLogVals(i->filters[id].num_idx_fields, vals);
	//reporter->Error("Result: %d", (uint64_t) idxhash->Hash());
	//reporter->Error("Hashing %d val fields", i->num_val_fields);
	HashKey* valhash = HashLogVals(i->filters[id].num_val_fields, vals+i->filters[id].num_idx_fields);
	//reporter->Error("Result: %d", (uint64_t) valhash->Hash());
	
	//reporter->Error("received entry with idxhash %d and valhash %d", (uint64_t) idxhash->Hash(), (uint64_t) valhash->Hash());

	InputHash *h = i->filters[id].lastDict->Lookup(idxhash);
	if ( h != 0 ) {
		// seen before
		if ( h->valhash->Hash() == valhash->Hash() ) {
			// ok, double.
			i->filters[id].lastDict->Remove(idxhash);
			i->filters[id].currDict->Insert(idxhash, h);
			return;
		} else {
			// updated
			i->filters[id].lastDict->Remove(idxhash);
			delete(h);
			updated = true;
			
		}
	}


	Val* idxval = LogValToIndexVal(i->filters[id].num_idx_fields, i->filters[id].itype, vals);
	Val* valval;
	
	int position = i->filters[id].num_idx_fields;
	if ( i->filters[id].num_val_fields == 1 && !i->filters[id].want_record ) {
		valval = LogValToVal(vals[position], i->filters[id].rtype->FieldType(0));
	} else {
		RecordVal * r = new RecordVal(i->filters[id].rtype);

		for ( int j = 0; j < i->filters[id].rtype->NumFields(); j++) {

			Val* val = 0;
			if ( i->filters[id].rtype->FieldType(j)->Tag() == TYPE_RECORD ) {
				val = LogValToRecordVal(vals, i->filters[id].rtype->FieldType(j)->AsRecordType(), &position);
			} else {
				val =  LogValToVal(vals[position], i->filters[id].rtype->FieldType(j));
				position++;
			}
			
			/* if ( val == 0 ) {
				reporter->InternalError("conversion error");
				return;
			} */

			r->Assign(j,val);

		}
		valval = r;
	}


	Val* oldval = 0;
	if ( updated == true ) {
			// in that case, we need the old value to send the event (if we send an event).
			oldval = i->filters[id].tab->Lookup(idxval);
	}


	// call filter first to determine if we really add / change the entry
	if ( i->filters[id].pred ) {
		EnumVal* ev;
		Ref(idxval);
		Ref(valval);

		if ( updated ) {
			ev = new EnumVal(BifEnum::Input::EVENT_CHANGED, BifType::Enum::Input::Event);
		} else {
			ev = new EnumVal(BifEnum::Input::EVENT_NEW, BifType::Enum::Input::Event);
		}
		
		val_list vl(3);
		vl.append(ev);
		vl.append(idxval);
		vl.append(valval);
		Val* v = i->filters[id].pred->Call(&vl);
		bool result = v->AsBool();
		Unref(v);

		if ( result == false ) {
			if ( !updated ) {
				// throw away. Hence - we quit. And remove the entry from the current dictionary...
				delete(i->filters[id].currDict->RemoveEntry(idxhash));
				return;
			} else {
				// keep old one
				i->filters[id].currDict->Insert(idxhash, h);
				return;
			}
		}

	}
	

	//i->tab->Assign(idxval, valval);
	HashKey* k = i->filters[id].tab->ComputeHash(idxval);
	if ( !k ) {
		reporter->InternalError("could not hash");
		return;
	}

	reporter->Error("assigning");
	i->filters[id].tab->Assign(idxval, k, valval);

	InputHash* ih = new InputHash();
	k = i->filters[id].tab->ComputeHash(idxval);
	ih->idxkey = k;
	ih->valhash = valhash;
	//i->tab->Delete(k);

	i->filters[id].currDict->Insert(idxhash, ih);

	// send events now that we are kind of finished.
	
	/* FIXME: fix me.
	std::list<string>::iterator filter_iterator = i->events.begin();
	while ( filter_iterator != i->events.end() ) {
		EnumVal* ev;
		Ref(idxval);

		if ( updated ) { // in case of update send back the old value.
			ev = new EnumVal(BifEnum::Input::EVENT_CHANGED, BifType::Enum::Input::Event);
			assert ( oldval != 0 );
			Ref(oldval);
			SendEvent(*filter_iterator, ev, idxval, oldval);
		} else {
			ev = new EnumVal(BifEnum::Input::EVENT_NEW, BifType::Enum::Input::Event);
			Ref(valval);
			SendEvent(*filter_iterator, ev, idxval, valval);
		}
			

		++filter_iterator;
	} */
}


void InputMgr::EndCurrentSend(const InputReader* reader, int id) {
	ReaderInfo *i = FindReader(reader);
	if ( i == 0 ) {
		reporter->InternalError("Unknown reader");
		return;
	}

	assert(i->HasFilter(id));

	// lastdict contains all deleted entries and should be empty apart from that
	IterCookie *c = i->filters[id].lastDict->InitForIteration();
	i->filters[id].lastDict->MakeRobustCookie(c);
	InputHash* ih;
	HashKey *lastDictIdxKey;
	//while ( ( ih = i->lastDict->NextEntry(c) ) ) {
	while ( ( ih = i->filters[id].lastDict->NextEntry(lastDictIdxKey, c) ) ) {

		if ( i->filters[id].pred ) {
			ListVal *idx = i->filters[id].tab->RecoverIndex(ih->idxkey);
			assert(idx != 0);
			Val *val = i->filters[id].tab->Lookup(idx);
			assert(val != 0);


			bool doBreak = false;
			// ask predicate, if we want to expire this element...

			EnumVal* ev = new EnumVal(BifEnum::Input::EVENT_REMOVED, BifType::Enum::Input::Event);
			Ref(idx);
			Ref(val);

			val_list vl(3);
			vl.append(ev);
			vl.append(idx);
			vl.append(val);
			Val* v = i->filters[id].pred->Call(&vl);
			bool result = v->AsBool();
			Unref(v);
			
			if ( result == false ) {
				// Keep it. Hence - we quit and simply go to the next entry of lastDict
				// ah well - and we have to add the entry to currDict...
				i->filters[id].currDict->Insert(lastDictIdxKey, i->filters[id].lastDict->RemoveEntry(lastDictIdxKey));
				continue;
			}


			// 

			{
				/* FIXME: events
				std::list<string>::iterator it = i->filters[id].events.begin();
				while ( it != i->filters[id].events.end() ) {
					Ref(idx);
					Ref(val);
					EnumVal *ev = new EnumVal(BifEnum::Input::EVENT_REMOVED, BifType::Enum::Input::Event);
					SendEvent(*it, ev, idx, val);
					++it;
				}
				*/
			}

		}

		i->filters[id].tab->Delete(ih->idxkey);
		i->filters[id].lastDict->Remove(lastDictIdxKey); // deletex in next line
		delete(ih);
	}

	i->filters[id].lastDict->Clear(); // should be empty... but... well... who knows...
	delete(i->filters[id].lastDict);

	i->filters[id].lastDict = i->filters[id].currDict;	
	i->filters[id].currDict = new PDict(InputHash);
}

void InputMgr::Put(const InputReader* reader, int id, const LogVal* const *vals) {
	ReaderInfo *i = FindReader(reader);
	if ( i == 0 ) {
		reporter->InternalError("Unknown reader");
		return;
	}

	assert(i->HasFilter(id));

	Val* idxval = LogValToIndexVal(i->filters[id].num_idx_fields, i->filters[id].itype, vals);
	Val* valval;
	
	int position = i->filters[id].num_idx_fields;
	if ( i->filters[id].num_val_fields == 1 && !i->filters[id].want_record ) {
		valval = LogValToVal(vals[i->filters[id].num_idx_fields], i->filters[id].rtype->FieldType(i->filters[id].num_idx_fields));
	} else {
		RecordVal * r = new RecordVal(i->filters[id].rtype);

		for ( int j = 0; j < i->filters[id].rtype->NumFields(); j++) {

			Val* val = 0;
			if ( i->filters[id].rtype->FieldType(j)->Tag() == TYPE_RECORD ) {
				val = LogValToRecordVal(vals, i->filters[id].rtype->FieldType(j)->AsRecordType(), &position);
			} else {
				val =  LogValToVal(vals[position], i->filters[id].rtype->FieldType(j));
				position++;
			}
			
			if ( val == 0 ) {
				reporter->InternalError("conversion error");
				return;
			}

			r->Assign(j,val);

		}
		valval = r;
	}

	i->filters[id].tab->Assign(idxval, valval);
}

void InputMgr::Clear(const InputReader* reader, int id) {
	ReaderInfo *i = FindReader(reader);
	if ( i == 0 ) {
		reporter->InternalError("Unknown reader");
		return;
	}

	assert(i->HasFilter(id));	

	i->filters[id].tab->RemoveAll();
}

bool InputMgr::Delete(const InputReader* reader, int id, const LogVal* const *vals) {
	ReaderInfo *i = FindReader(reader);
	if ( i == 0 ) {
		reporter->InternalError("Unknown reader");
		return false;
	}

	assert(i->HasFilter(id));			

	Val* idxval = LogValToIndexVal(i->filters[id].num_idx_fields, i->filters[id].itype, vals);

	return ( i->filters[id].tab->Delete(idxval) != 0 );
} 

void InputMgr::Error(InputReader* reader, const char* msg)
{
	reporter->Error("error with input reader for %s: %s", reader->Source().c_str(), msg);
}

/* Does not work atm, because LogValToVal needs BroType
void InputMgr::SendEvent(const string& name, const int num_vals, const LogVal* const *vals) 
{
	EventHandler* handler = event_registry->Lookup(name.c_str());
	if ( handler == 0 ) {
		reporter->Error("Event %s not found", name.c_str());
		return;
	}

	val_list* vl = new val_list;
	for ( int i = 0; i < num_vals; i++) {
		vl->append(LogValToVal(vals[i]));
	}

	mgr.Dispatch(new Event(handler, vl));
} */

void InputMgr::SendEvent(const string& name, EnumVal* event, Val* left, Val* right) 
{
	EventHandler* handler = event_registry->Lookup(name.c_str());
	if ( handler == 0 ) {
		reporter->Error("Event %s not found", name.c_str());
		return;
	}

	val_list* vl = new val_list;
	vl->append(event);
	vl->append(left);
	vl->append(right);

	mgr.Dispatch(new Event(handler, vl));
}


Val* InputMgr::LogValToRecordVal(const LogVal* const *vals, RecordType *request_type, int* position) {
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
			fieldVal = LogValToRecordVal(vals, request_type->FieldType(i)->AsRecordType(), position);	
		} else {
			fieldVal = LogValToVal(vals[*position], request_type->FieldType(i));
			(*position)++;
		}

		rec->Assign(i, fieldVal);
	}

	return rec;

} 


int InputMgr::GetLogValLength(const LogVal* val) {
	int length = 0;

	switch (val->type) {
	case TYPE_BOOL:
	case TYPE_INT:
		length += sizeof(val->val.int_val);
		break;

	case TYPE_COUNT:
	case TYPE_COUNTER:
	case TYPE_PORT:
		length += sizeof(val->val.uint_val);
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
			length += GetLogValLength(val->val.set_val.vals[i]);
		}
		break;
		}

	case TYPE_VECTOR: {
		int j = val->val.vector_val.size;
		for ( int i = 0; i < j; i++ ) {
			length += GetLogValLength(val->val.vector_val.vals[i]);
		}
		break;
		}

	default:
		reporter->InternalError("unsupported type %d for GetLogValLength", val->type);
	}

	return length;
	
}

int InputMgr::CopyLogVal(char *data, const int startpos, const LogVal* val) {
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
	case TYPE_PORT:
		//*(data+startpos) = val->val.uint_val;
		memcpy(data+startpos, (const void*) &(val->val.uint_val), sizeof(val->val.uint_val));
		return sizeof(val->val.uint_val);
		break;

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
		memcpy(data+startpos, (const char*) &(val->val.subnet_val.net), sizeof(val->val.subnet_val.net) );
		length += sizeof(val->val.subnet_val.net);		
		return length;
		break;
		}

	case TYPE_TABLE: {
		int length = 0;
		for ( int i = 0; i < val->val.set_val.size; i++ ) {
			length += CopyLogVal(data, startpos+length, val->val.set_val.vals[i]);
		}
		return length;
		break;				 
		}

	case TYPE_VECTOR: {
		int length = 0;
		int j = val->val.vector_val.size;
		for ( int i = 0; i < j; i++ ) {
			length += CopyLogVal(data, startpos+length, val->val.vector_val.vals[i]);
		}
		return length;
		break;				 
		}

	default:
		reporter->InternalError("unsupported type %d for CopyLogVal", val->type);
		return 0;
	}
	
	reporter->InternalError("internal error");
	return 0;

}

HashKey* InputMgr::HashLogVals(const int num_elements, const LogVal* const *vals) {
	int length = 0;

	for ( int i = 0; i < num_elements; i++ ) {
		const LogVal* val = vals[i];
		length += GetLogValLength(val);
	}

	//reporter->Error("Length: %d", length);

	int position = 0;
	char *data = (char*) malloc(length);
	if ( data == 0 ) {
		reporter->InternalError("Could not malloc?");
	}
	for ( int i = 0; i < num_elements; i++ ) {
		const LogVal* val = vals[i];
		position += CopyLogVal(data, position, val);
	}

	assert(position == length);
	return new HashKey(data, length);


}

Val* InputMgr::LogValToVal(const LogVal* val, BroType* request_type) {
	
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
		return new PortVal(val->val.uint_val);
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
			t->Assign(LogValToVal( val->val.set_val.vals[i], type ), 0);
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
			v->Assign(i, LogValToVal( val->val.set_val.vals[i], type ), 0);
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
		
InputMgr::ReaderInfo* InputMgr::FindReader(const InputReader* reader)
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

		
InputMgr::ReaderInfo* InputMgr::FindReader(const EnumVal* id)
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


string InputMgr::Hash(const string &input) {
	unsigned char digest[16];
	hash_md5(input.length(), (const unsigned char*) input.c_str(), digest);
	string out((const char*) digest, 16);
	return out;
}


