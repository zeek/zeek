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


class InputHash {
public:
	HashKey* valhash;
	HashKey* idxkey; // does not need ref or whatever - if it is present here, it is also still present in the TableVal.
};

declare(PDict, InputHash);

struct InputMgr::Filter {
	EnumVal* id;	
	string name;
	Func* pred;	

	~Filter();
};

InputMgr::Filter::~Filter() {
	Unref(id);
}

struct InputMgr::ReaderInfo {
	EnumVal* id;
	EnumVal* type;
	InputReader* reader;
	unsigned int num_idx_fields;
	unsigned int num_val_fields;

	TableVal* tab;
	RecordType* rtype;
	RecordType* itype;

	PDict(InputHash)* currDict;
	PDict(InputHash)* lastDict;
	
	list<string> events; // events we fire when "something" happens
	list<InputMgr::Filter> filters; // filters that can prevent our actions

	~ReaderInfo();
	};

InputMgr::ReaderInfo::~ReaderInfo() {
	Unref(type);
	Unref(tab);
	Unref(itype);
	Unref(rtype);
	Unref(id);

	delete(reader);	
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
InputReader* InputMgr::CreateReader(EnumVal* id, RecordVal* description) 
{
	InputReaderDefinition* ir = input_readers;
	
	RecordType* rtype = description->Type()->AsRecordType();
	if ( ! same_type(rtype, BifType::Record::Input::ReaderDescription, 0) )
	{
		reporter->Error("readerDescription argument not of right type");
		return 0;
	}

	EnumVal* reader = description->Lookup(rtype->FieldOffset("reader"))->AsEnumVal();
	
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

	RecordType *idx = description->Lookup(rtype->FieldOffset("idx"))->AsType()->AsTypeType()->Type()->AsRecordType();
	RecordType *val = description->Lookup(rtype->FieldOffset("val"))->AsType()->AsTypeType()->Type()->AsRecordType();
	TableVal *dst = description->Lookup(rtype->FieldOffset("destination"))->AsTableVal();


	vector<LogField*> fieldsV; // vector, because we don't know the length beforehands
	

	bool status = !UnrollRecordType(&fieldsV, idx, "");

	int idxfields = fieldsV.size();
	
	status = status || !UnrollRecordType(&fieldsV, val, "");
	int valfields = fieldsV.size() - idxfields;

	if ( status ) {
		reporter->Error("Problem unrolling");
		return 0;
	}
	
	
	LogField** fields = new LogField*[fieldsV.size()];
	for ( unsigned int i = 0; i < fieldsV.size(); i++ ) {
		fields[i] = fieldsV[i];
	}

	ReaderInfo* info = new ReaderInfo;
	info->reader = reader_obj;
	info->type = reader->Ref()->AsEnumVal();
	info->num_idx_fields = idxfields;
	info->num_val_fields = valfields;
	info->tab = dst->Ref()->AsTableVal();
	info->rtype = val->Ref()->AsRecordType();
	info->id = id->Ref()->AsEnumVal();
	info->itype = idx->Ref()->AsRecordType();
	info->currDict = new PDict(InputHash);
	info->lastDict = new PDict(InputHash);

	readers.push_back(info);

	int success = reader_obj->Init(source, fieldsV.size(), idxfields, fields);
	if ( success == false ) {
		assert( RemoveReader(id) );
		return 0;
	}
	success = reader_obj->Update();
	if ( success == false ) {
		assert ( RemoveReader(id) );
		return 0;
	}
	
	return reader_obj;
	
}
bool InputMgr::IsCompatibleType(BroType* t)
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
	case TYPE_RECORD:
		// for record: check, if all elements are compatible? But... LogMgr also doesn't do this.
		// ^ recursive checking is done in UnrollRecordType.
		return true;
	
	case TYPE_FILE:
	case TYPE_FUNC:
		return false;


	case TYPE_TABLE:
		return false;

	case TYPE_VECTOR:
		{
		return IsCompatibleType(t->AsVectorType()->YieldType());
		}

	default:
		return false;
	}

	return false;
	}

bool InputMgr::RemoveReader(const EnumVal* id) {
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

bool InputMgr::RegisterEvent(const EnumVal* id, string eventName) {
	ReaderInfo *i = FindReader(id);
	if ( i == 0 ) {
		reporter->InternalError("Reader not found");
		return false;
	}
	
	i->events.push_back(eventName);

	return true;
}

// remove first event with name eventName
// (though there shouldn't really be several events with the same name...
bool InputMgr::UnregisterEvent(const EnumVal* id, string eventName) {
	ReaderInfo *i = FindReader(id);
	if ( i == 0 ) {
		reporter->InternalError("Reader not found");
		return false;
	}
	
	std::list<string>::iterator it = i->events.begin();
	while ( it != i->events.end() ) 
	{
		if ( *it == eventName ) {
			it = i->events.erase(it);
			return true;
		}
		else 
			++it;
	}

	return false;
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

bool InputMgr::AddFilter(EnumVal *id, RecordVal* fval) {
	ReaderInfo *i = FindReader(id);
	if ( i == 0 ) {
		reporter->Error("Reader not found");
		return false;
	}

	RecordType* rtype = fval->Type()->AsRecordType();
	if ( ! same_type(rtype, BifType::Record::Input::Filter, 0) )
	{
		reporter->Error("filter argument not of right type");
		return false;
	}


	Val* name = fval->Lookup(rtype->FieldOffset("name"));
	Val* pred = fval->Lookup(rtype->FieldOffset("pred"));

	Filter filter;
	filter.name = name->AsString()->CheckString();
	filter.id = id->Ref()->AsEnumVal();
	filter.pred = pred ? pred->AsFunc() : 0;

	i->filters.push_back(filter);

	return true;
}

bool InputMgr::RemoveFilter(EnumVal* id, const string &name) {
	ReaderInfo *i = FindReader(id);
	if ( i == 0 ) {
		reporter->Error("Reader not found");
		return false;
	}


	std::list<InputMgr::Filter>::iterator it = i->filters.begin();
	while ( it != i->filters.end() ) 
	{
		if ( (*it).name == name ) {
			it = i->filters.erase(it);
			return true;
			break;
		}
		else 
			++it;
	}

	return false;;
}



Val* InputMgr::LogValToIndexVal(int num_fields, const RecordType *type, const LogVal* const *vals) {
	Val* idxval;
	int position = 0;


	if ( num_fields == 1 && type->FieldType(0)->Tag() != TYPE_RECORD  ) {
		idxval = LogValToVal(vals[0]);
		position = 1;
	} else {
		ListVal *l = new ListVal(TYPE_ANY);
		for ( int j = 0 ; j < type->NumFields(); j++ ) {
			if ( type->FieldType(j)->Tag() == TYPE_RECORD ) {
				l->Append(LogValToRecordVal(vals, type->FieldType(j)->AsRecordType(), &position));
			} else {
				l->Append(LogValToVal(vals[position], type->FieldType(j)->Tag()));
				position++;
			}
		}
		idxval = l;
	}

	//reporter->Error("Position: %d, num_fields: %d", position, num_fields);
	assert ( position == num_fields );

	return idxval;
}


void InputMgr::SendEntry(const InputReader* reader, const LogVal* const *vals) {
	ReaderInfo *i = FindReader(reader);
	if ( i == 0 ) {
		reporter->InternalError("Unknown reader");
		return;
	}

	bool updated = false;


	//reporter->Error("Hashing %d index fields", i->num_idx_fields);
	HashKey* idxhash = HashLogVals(i->num_idx_fields, vals);
	//reporter->Error("Result: %d", (uint64_t) idxhash->Hash());
	//reporter->Error("Hashing %d val fields", i->num_val_fields);
	HashKey* valhash = HashLogVals(i->num_val_fields, vals+i->num_idx_fields);
	//reporter->Error("Result: %d", (uint64_t) valhash->Hash());
	
	//reporter->Error("received entry with idxhash %d and valhash %d", (uint64_t) idxhash->Hash(), (uint64_t) valhash->Hash());

	InputHash *h = i->lastDict->Lookup(idxhash);
	if ( h != 0 ) {
		// seen before
		if ( h->valhash->Hash() == valhash->Hash() ) {
			// ok, double.
			i->lastDict->Remove(idxhash);
			i->currDict->Insert(idxhash, h);
			return;
		} else {
			// updated
			i->lastDict->Remove(idxhash);
			delete(h);
			updated = true;
			
		}
	}


	Val* idxval = LogValToIndexVal(i->num_idx_fields, i->itype, vals);
	Val* valval;
	
	int position = i->num_idx_fields;
	if ( i->num_val_fields == 1 ) {
		valval = LogValToVal(vals[i->num_idx_fields]);
	} else {
		RecordVal * r = new RecordVal(i->rtype);

		/* if ( i->rtype->NumFields() != (int) i->num_val_fields ) {
			reporter->InternalError("Type mismatch");
			return;
		} */

		for ( int j = 0; j < i->rtype->NumFields(); j++) {

			Val* val = 0;
			if ( i->rtype->FieldType(j)->Tag() == TYPE_RECORD ) {
				val = LogValToRecordVal(vals, i->rtype->FieldType(j)->AsRecordType(), &position);
			} else {
				val =  LogValToVal(vals[position], i->rtype->FieldType(j)->Tag());
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


	Val* oldval = 0;
	if ( updated == true ) {
			// in that case, we need the old value to send the event (if we send an event).
			oldval = i->tab->Lookup(idxval);
	}


	// call filters first do determine if we really add / change the entry
	std::list<InputMgr::Filter>::iterator it = i->filters.begin();
	while ( it != i->filters.end() ) {
		if (! (*it).pred ) {
			continue;
		}

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
		Val* v = (*it).pred->Call(&vl);
		bool result = v->AsBool();
		Unref(v);

		if ( result == false ) {
			if ( !updated ) {
				// throw away. Hence - we quit. And remove the entry from the current dictionary...
				delete(i->currDict->RemoveEntry(idxhash));
				return;
			} else {
				// keep old one
				i->currDict->Insert(idxhash, h);
				return;
			}
		}

		++it;
	}
	

	//i->tab->Assign(idxval, valval);
	HashKey* k = i->tab->ComputeHash(idxval);
	if ( !k ) {
		reporter->InternalError("could not hash");
		return;
	}

	i->tab->Assign(idxval, k, valval);

	InputHash* ih = new InputHash();
	k = i->tab->ComputeHash(idxval);
	ih->idxkey = k;
	ih->valhash = valhash;
	//i->tab->Delete(k);

	i->currDict->Insert(idxhash, ih);

	// send events now that we are kind of finished.
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
	}
}


void InputMgr::EndCurrentSend(const InputReader* reader) {
	ReaderInfo *i = FindReader(reader);
	if ( i == 0 ) {
		reporter->InternalError("Unknown reader");
		return;
	}
	// lastdict contains all deleted entries and should be empty apart from that
	IterCookie *c = i->lastDict->InitForIteration();
	i->lastDict->MakeRobustCookie(c);
	InputHash* ih;
	HashKey *lastDictIdxKey;
	//while ( ( ih = i->lastDict->NextEntry(c) ) ) {
	while ( ( ih = i->lastDict->NextEntry(lastDictIdxKey, c) ) ) {
	
		if ( i->events.size() != 0 || i->filters.size() != 0 )  // we have a filter or an event
		{

			ListVal *idx = i->tab->RecoverIndex(ih->idxkey);
			assert(idx != 0);
			Val *val = i->tab->Lookup(idx);
			assert(val != 0);


			{	
				bool doBreak = false;
				// ask filter, if we want to expire this element...
				std::list<InputMgr::Filter>::iterator it = i->filters.begin();
				while ( it != i->filters.end() ) {
					if (! (*it).pred ) {
						continue;
					}

					EnumVal* ev = new EnumVal(BifEnum::Input::EVENT_REMOVED, BifType::Enum::Input::Event);
					Ref(idx);
					Ref(val);

					val_list vl(3);
					vl.append(ev);
					vl.append(idx);
					vl.append(val);
					Val* v = (*it).pred->Call(&vl);
					bool result = v->AsBool();
					Unref(v);
					
					++it;

					if ( result == false ) {
						// Keep it. Hence - we quit and simply go to the next entry of lastDict
						// ah well - and we have to add the entry to currDict...
						i->currDict->Insert(lastDictIdxKey, i->lastDict->RemoveEntry(lastDictIdxKey));
						doBreak = true;
						continue;
					}

				}

				if ( doBreak ) {
					continue;
				}
			}
		
			// 

			{
				std::list<string>::iterator it = i->events.begin();
				while ( it != i->events.end() ) {
					Ref(idx);
					Ref(val);
					EnumVal *ev = new EnumVal(BifEnum::Input::EVENT_REMOVED, BifType::Enum::Input::Event);
					SendEvent(*it, ev, idx, val);
					++it;
				}
			}

		}

		i->tab->Delete(ih->idxkey);
		i->lastDict->Remove(lastDictIdxKey); // deletex in next line
		delete(ih);
	}

	i->lastDict->Clear(); // should be empty... but... well... who knows...
	delete(i->lastDict);

	i->lastDict = i->currDict;	
	i->currDict = new PDict(InputHash);
}

void InputMgr::Put(const InputReader* reader, const LogVal* const *vals) {
	ReaderInfo *i = FindReader(reader);
	if ( i == 0 ) {
		reporter->InternalError("Unknown reader");
		return;
	}

	Val* idxval = LogValToIndexVal(i->num_idx_fields, i->itype, vals);
	Val* valval;
	
	int position = i->num_idx_fields;
	if ( i->num_val_fields == 1 ) {
		valval = LogValToVal(vals[i->num_idx_fields]);
	} else {
		RecordVal * r = new RecordVal(i->rtype);

		for ( int j = 0; j < i->rtype->NumFields(); j++) {

			Val* val = 0;
			if ( i->rtype->FieldType(j)->Tag() == TYPE_RECORD ) {
				val = LogValToRecordVal(vals, i->rtype->FieldType(j)->AsRecordType(), &position);
			} else {
				val =  LogValToVal(vals[position], i->rtype->FieldType(j)->Tag());
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

	i->tab->Assign(idxval, valval);
}

void InputMgr::Clear(const InputReader* reader) {
	ReaderInfo *i = FindReader(reader);
	if ( i == 0 ) {
		reporter->InternalError("Unknown reader");
		return;
	}
	
	i->tab->RemoveAll();
}

bool InputMgr::Delete(const InputReader* reader, const LogVal* const *vals) {
	ReaderInfo *i = FindReader(reader);
	if ( i == 0 ) {
		reporter->InternalError("Unknown reader");
		return false;
	}
	
	Val* idxval = LogValToIndexVal(i->num_idx_fields, i->itype, vals);

	return ( i->tab->Delete(idxval) != 0 );
} 

void InputMgr::Error(InputReader* reader, const char* msg)
{
	reporter->Error("error with input reader for %s: %s", reader->Source().c_str(), msg);
}


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
}

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
			fieldVal = LogValToVal(vals[*position], request_type->FieldType(i)->Tag());
			(*position)++;
		}

		rec->Assign(i, fieldVal);
	}

	return rec;

} 

HashKey* InputMgr::HashLogVals(const int num_elements, const LogVal* const *vals) {
	int length = 0;

	for ( int i = 0; i < num_elements; i++ ) {
		const LogVal* val = vals[i];
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

		default:
			reporter->InternalError("unsupported type for hashlogvals");
		}
		
	}

	//reporter->Error("Length: %d", length);

	int position = 0;
	char *data = (char*) malloc(length);
	if ( data == 0 ) {
		reporter->InternalError("Could not malloc?");
	}
	for ( int i = 0; i < num_elements; i++ ) {
		const LogVal* val = vals[i];
		switch ( val->type ) {
		case TYPE_BOOL:
		case TYPE_INT:
			//reporter->Error("Adding field content to pos %d: %lld", val->val.int_val, position); 
			memcpy(data+position, (const void*) &(val->val.int_val), sizeof(val->val.int_val));
			//*(data+position) = val->val.int_val;
			position += sizeof(val->val.int_val);
			break;

		case TYPE_COUNT:
		case TYPE_COUNTER:
		case TYPE_PORT:
			//*(data+position) = val->val.uint_val;
			memcpy(data+position, (const void*) &(val->val.uint_val), sizeof(val->val.uint_val));
			position += sizeof(val->val.uint_val);
			break;
	
		case TYPE_DOUBLE:
		case TYPE_TIME:
		case TYPE_INTERVAL:
			//*(data+position) = val->val.double_val;
			memcpy(data+position, (const void*) &(val->val.double_val), sizeof(val->val.double_val));
			position += sizeof(val->val.double_val);
			break;

		case TYPE_STRING:
		case TYPE_ENUM:
			{
			memcpy(data+position, val->val.string_val->c_str(), val->val.string_val->length());
			position += val->val.string_val->size();
			break;
			}
	
		case TYPE_ADDR:
			memcpy(data+position, val->val.addr_val, NUM_ADDR_WORDS*sizeof(uint32_t));
			position += NUM_ADDR_WORDS*sizeof(uint32_t);
			break;

		case TYPE_SUBNET:
			memcpy(data+position,(const char*)  &(val->val.subnet_val.width), sizeof(val->val.subnet_val.width) );
			position += sizeof(val->val.subnet_val.width);
			memcpy(data+position, (const char*) &(val->val.subnet_val.net), sizeof(val->val.subnet_val.net) );
			position += sizeof(val->val.subnet_val.net);		
			break;

		default:
			reporter->InternalError("unsupported type for hashlogvals2");
		}

		
	}

	assert(position == length);
	return new HashKey(data, length);


}

Val* InputMgr::LogValToVal(const LogVal* val, TypeTag request_type) {
	
	if ( request_type != TYPE_ANY && request_type != val->type ) {
		reporter->InternalError("Typetags don't match: %d vs %d", request_type, val->type);
		return 0;
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

	case TYPE_ENUM:
		reporter->InternalError("Sorry, Enums reading does not yet work, missing internal inferface");
		

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


