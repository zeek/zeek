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

void InputReader::Put(const LogVal* const *val) 
{
	input_mgr->Put(this, val);
}

void InputReader::Clear() 
{
	input_mgr->Clear(this);
}

void InputReader::Delete(const LogVal* const *val) 
{
	input_mgr->Delete(this, val);
}


bool InputReader::Init(string arg_source, int arg_num_fields, int arg_idx_fields,
					   const LogField* const * arg_fields) 
{
	source = arg_source;
	num_fields = arg_num_fields;
	index_fields = arg_idx_fields;
	fields = arg_fields;

	// disable if DoInit returns error.
	disabled = !DoInit(arg_source, arg_num_fields, arg_idx_fields, arg_fields);
	return !disabled;
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


void InputReader::SendEntry(const LogVal* const *vals)
{
	input_mgr->SendEntry(this, vals);
}

void InputReader::EndCurrentSend() 
{
	input_mgr->EndCurrentSend(this);
}
