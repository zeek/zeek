// See the file "COPYING" in the main distribution directory for copyright.

#include "ReaderBackend.h"
#include "ReaderFrontend.h"
#include "Manager.h"

using threading::Value;
using threading::Field;

namespace input {

class ErrorMessage : public threading::OutputMessage<ReaderFrontend> {
public:
	ErrorMessage(ReaderFrontend* reader, string message)
		: threading::OutputMessage<ReaderFrontend>("Error", reader),
		message(message) {}

	virtual bool Process() {
		input_mgr->Error(Object(), message.c_str());
		return true;
	}

private:
	string message;
};

class PutMessage : public threading::OutputMessage<ReaderFrontend> {
public:
	PutMessage(ReaderFrontend* reader, int id, const Value* const *val)
		: threading::OutputMessage<ReaderFrontend>("Put", reader),
		id(id), val(val) {}

	virtual bool Process() {
		input_mgr->Put(Object(), id, val);
		return true;
	}

private:
	int id;
	const Value* const *val;
};

class DeleteMessage : public threading::OutputMessage<ReaderFrontend> {
public:
	DeleteMessage(ReaderFrontend* reader, int id, const Value* const *val)
		: threading::OutputMessage<ReaderFrontend>("Delete", reader),
		id(id), val(val) {}

	virtual bool Process() {
		return input_mgr->Delete(Object(), id, val);
	}

private:
	int id;
	const Value* const *val;
};

class ClearMessage : public threading::OutputMessage<ReaderFrontend> {
public:
	ClearMessage(ReaderFrontend* reader, int id)
		: threading::OutputMessage<ReaderFrontend>("Clear", reader),
		id(id) {}

	virtual bool Process() {
		input_mgr->Clear(Object(), id);
		return true;
	}

private:
	int id;
};

class SendEventMessage : public threading::OutputMessage<ReaderFrontend> {
public:
	SendEventMessage(ReaderFrontend* reader, const string& name, const int num_vals, const Value* const *val)
		: threading::OutputMessage<ReaderFrontend>("SendEvent", reader),
		name(name), num_vals(num_vals), val(val) {}

	virtual bool Process() {
		return input_mgr->SendEvent(name, num_vals, val);
	}

private:
	const string name;
	const int num_vals;
	const Value* const *val;
};

class SendEntryMessage : public threading::OutputMessage<ReaderFrontend> {
public:
	SendEntryMessage(ReaderFrontend* reader, const int id, const Value* const *val)
		: threading::OutputMessage<ReaderFrontend>("SendEntry", reader),
		id(id), val(val) {}

	virtual bool Process() {
		input_mgr->SendEntry(Object(), id, val);
		return true;
	}

private:
	const int id;
	const Value* const *val;
};

class EndCurrentSendMessage : public threading::OutputMessage<ReaderFrontend> {
public:
	EndCurrentSendMessage(ReaderFrontend* reader, int id)
		: threading::OutputMessage<ReaderFrontend>("SendEntry", reader),
		id(id) {}

	virtual bool Process() {
		input_mgr->EndCurrentSend(Object(), id);
		return true;
	}

private:
	int id;
};

ReaderBackend::ReaderBackend(ReaderFrontend* arg_frontend) : MsgThread()
{
	buf = 0;
	buf_len = 1024;
	disabled = true; // disabled will be set correcty in init.

	frontend = arg_frontend;

	SetName(frontend->Name());
}

ReaderBackend::~ReaderBackend() 
{
	
}

void ReaderBackend::Error(const string &msg)
{
	SendOut(new ErrorMessage(frontend, msg));
}

/*
void ReaderBackend::Error(const char *msg)
{
	SendOut(new ErrorMessage(frontend, string(msg)));
} */


void ReaderBackend::Put(int id, const Value* const *val) 
{
	SendOut(new PutMessage(frontend, id, val));
}

void ReaderBackend::Delete(int id, const Value* const *val) 
{
	SendOut(new DeleteMessage(frontend, id, val));
}

void ReaderBackend::Clear(int id) 
{
	SendOut(new ClearMessage(frontend, id));
}

void ReaderBackend::SendEvent(const string& name, const int num_vals, const Value* const *vals) 
{
	SendOut(new SendEventMessage(frontend, name, num_vals, vals));
} 

void ReaderBackend::EndCurrentSend(int id) 
{
	SendOut(new EndCurrentSendMessage(frontend, id));
}

void ReaderBackend::SendEntry(int id, const Value* const *vals)
{
	SendOut(new SendEntryMessage(frontend, id, vals));
}

bool ReaderBackend::Init(string arg_source) 
{
	source = arg_source;

	// disable if DoInit returns error.
	disabled = !DoInit(arg_source);
	return !disabled;
}

bool ReaderBackend::AddFilter(int id, int arg_num_fields,
					   const Field* const * arg_fields) 
{
	return DoAddFilter(id, arg_num_fields, arg_fields);
}

bool ReaderBackend::RemoveFilter(int id) 
{
	return DoRemoveFilter(id);
}

void ReaderBackend::Finish() 
{
	DoFinish();
	disabled = true;
}

bool ReaderBackend::Update() 
{
	return DoUpdate();
}


// stolen from logwriter
const char* ReaderBackend::Fmt(const char* format, ...)
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



}
