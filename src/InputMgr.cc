// See the file "COPYING" in the main distribution directory for copyright.

#include <algorithm>

#include "InputMgr.h"
#include "Event.h"
#include "EventHandler.h"
#include "NetVar.h"
#include "Net.h"


#include "InputReader.h"

#include "InputReaderAscii.h"


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
	DBG_LOG(DBG_LOGGING, "this has to happen");
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
	
	reader_obj->Init(source, 0, NULL);
	
	return reader_obj;
	
}

void InputMgr::Error(InputReader* reader, const char* msg)
{
	reporter->Error(fmt("error with input reader for %s: %s",
						reader->Source().c_str(), msg));
}

/*
 TODO:

void InputMgr::SendEvent(string name) {
 //EventHandler* handler = event_registry->Lookup(eventName.c_str());
 
 //if ( handler == 0 ) {
 //	reporter->Error("Event %s not found", eventName.c_str());
 //	return false;
 //}
 
 //val_list* vl = new val_list;
 //vl->append(new Val(12, TYPE_COUNT));
 
 //mgr.Dispatch(new Event(handler, vl));

	
}
 
*/


		
		
