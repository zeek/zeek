// See the file "COPYING" in the main distribution directory for copyright.

#include "InputReader.h"

InputReader::InputReader()
{
	buf = 0;
	buf_len = 1024;
	disabled = true; // disabled will be set correcty in init.
}

InputReader::~InputReader() 
{
	
}

void InputReader::Error(const char *msg)
{
	input_mgr->Error(this, msg);
}

void InputReader::Error(const string &msg)
{
	input_mgr->Error(this, msg.c_str());
}

void InputReader::Put(int id, const LogVal* const *val) 
{
	input_mgr->Put(this, int id, val);
}

void InputReader::Clear(int id) 
{
	input_mgr->Clear(this, int id);
}

void InputReader::Delete(int id, const LogVal* const *val) 
{
	input_mgr->Delete(this, int id, val);
}


bool InputReader::Init(string arg_source) 
{
	source = arg_source;

	// disable if DoInit returns error.
	disabled = !DoInit(arg_source);
	return !disabled;
}

bool InputReader::AddFilter(int id, int arg_num_fields,
					   const LogField* const * arg_fields) 
{
	return DoAddFilter(int id, arg_num_fields, arg_fields);
}

bool InputReader::RemoveFilter(int id) 
{
	return DoRemoveFilter(int id);
}

void InputReader::Finish() 
{
	DoFinish();
	disabled = true;
}

bool InputReader::Update() 
{
	return DoUpdate();
}

/* 
void InputReader::SendEvent(const string& name, const int num_vals, const LogVal* const *vals) 
{
	input_mgr->SendEvent(name, num_vals, vals);
} */

// stolen from logwriter
const char* InputReader::Fmt(const char* format, ...)
	{
	if ( ! buf )
		buf = (char*) malloc(buf_len);

	va_list al;
	va_start(al, format);
	int n = safe_vsnprintf(buf, buf_len, format, al);
	va_end(al);

	if ( (unsigned int) n >= buf_len )
		{ // Not enough room, grow the buffer.
		buf_len = n + 32;
		buf = (char*) realloc(buf, buf_len);

		// Is it portable to restart?
		va_start(al, format);
		n = safe_vsnprintf(buf, buf_len, format, al);
		va_end(al);
		}

	return buf;
	}


void InputReader::SendEntry(int id, const LogVal* const *vals)
{
	input_mgr->SendEntry(this, int id, vals);
}

void InputReader::EndCurrentSend(int id) 
{
	input_mgr->EndCurrentSend(this, int id);
}
