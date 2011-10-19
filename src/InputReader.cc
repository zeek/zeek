
#include "InputReader.h"
// #include "EventRegistry.h"
// #include "Event.h"

InputReader::InputReader()
{
    
}

InputReader::~InputReader() 
{
	
}

void InputReader::Error(const char *msg)
{
	input_mgr->Error(this, msg);
}

bool InputReader::Init(string source, string eventName) {
	//EventHandler* handler = event_registry->Lookup(eventName.c_str());
		
	//if ( handler == 0 ) {
	//	reporter->Error("Event %s not found", eventName.c_str());
	//	return false;
	//}
	
	//val_list* vl = new val_list;
	//vl->append(new Val(12, TYPE_COUNT));
	
	//mgr.Dispatch(new Event(handler, vl));
	return true;
}