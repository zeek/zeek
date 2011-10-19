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
InputReader* InputMgr::CreateReader(EnumVal* reader, string source, string eventName, RecordVal* eventDescription) 
{
	InputReaderDefinition* ir = input_readers;
	
	RecordType* rtype = eventDescription->Type()->AsRecordType();
	if ( ! same_type(rtype, BifType::Record::Input::Event, 0) )
	{
		reporter->Error("eventDescription argument not of right type");
		return 0;
	}
	
	while ( true ) {
		if ( ir->type == BifEnum::Input::READER_DEFAULT ) 
		{
			DBG_LOG(DBG_LOGGING, "unknown reader when creating reader");
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
	
	return reader_obj;
	
}

void InputMgr::Error(InputReader* reader, const char* msg)
{
	reporter->Error(fmt("error with input reader for %s: %s",
						reader->Source().c_str(), msg));
}


		
		
