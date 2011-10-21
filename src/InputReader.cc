
#include "InputReader.h"
// #include "EventRegistry.h"
// #include "Event.h"

InputReader::InputReader()
{
    disabled = true; // disabled will be set correcty in init.
}

InputReader::~InputReader() 
{
	
}

void InputReader::Error(const char *msg)
{
	input_mgr->Error(this, msg);
}

bool InputReader::Init(string arg_source, int arg_num_fields,
					   const LogField* const * arg_fields) 
{
	source = arg_source;
	num_fields = arg_num_fields;
	fields = arg_fields;

	// disable if DoInit returns error.
	disabled = !DoInit(arg_source, arg_num_fields, arg_fields);
	return !disabled;
}

void InputReader::Finish() {
	DoFinish();
}