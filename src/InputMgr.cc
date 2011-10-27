// See the file "COPYING" in the main distribution directory for copyright.

#include <algorithm>

#include "InputMgr.h"
#include "Event.h"
#include "EventHandler.h"
#include "NetVar.h"
#include "Net.h"


#include "InputReader.h"

#include "InputReaderAscii.h"

struct InputMgr::ReaderInfo {
	EnumVal* id;
	EnumVal* type;
	InputReader* reader;
	unsigned int num_idx_fields;
	unsigned int num_val_fields;

	TableVal* tab;

	};

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
	//DBG_LOG(DBG_LOGGING, "this has to happen");
}


// create a new input reader object to be used at whomevers leisure lateron.
InputReader* InputMgr::CreateReader(EnumVal* reader, RecordVal* description) 
{
	InputReaderDefinition* ir = input_readers;
	
	RecordType* rtype = description->Type()->AsRecordType();
	if ( ! same_type(rtype, BifType::Record::Input::ReaderDescription, 0) )
	{
		reporter->Error("readerDescription argument not of right type");
		return 0;
	}
	
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

	LogField** fields = new LogField*[idx->NumFields() + val->NumFields()];
	for ( int i = 0; i < idx->NumFields(); i++ ) 
	{
		// FIXME: do type checking...
		LogField* field = new LogField();
		field->name = idx->FieldName(i);
		field->type = idx->FieldType(i)->Tag();
		fields[i] = field;
	}
	for ( int i = 0; i < val->NumFields(); i++ ) 
	{
		// FIXME: do type checking...
		LogField* field = new LogField();
		field->name = val->FieldName(i);
		field->type = val->FieldType(i)->Tag();
		fields[idx->NumFields() + i] = field;
	}

	ReaderInfo* info = new ReaderInfo;
	info->reader = reader_obj;
	info->type = reader;
	info->num_idx_fields = idx->NumFields();
	info->num_val_fields = val->NumFields();
	info->tab = dst;
	readers.push_back(info);


	reader_obj->Init(source, idx->NumFields() + val->NumFields(), fields);
	reader_obj->Update();
	
	return reader_obj;
	
}

void InputMgr::Put(const InputReader* reader, const LogVal* const *vals) {
	ReaderInfo *i = FindReader(reader);
	if ( i == 0 ) {
		reporter->InternalError("Unknown reader");
		return;
	}

	i->tab->Assign(LogValToVal(vals[0]), LogValToVal(vals[1]));
	reporter->Error("assigned");
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

Val* InputMgr::LogValToVal(const LogVal* val) {
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
		if ( (*s)->reader == reader ) 
		{
			return *s;
		}
		}

	return 0;
	}

