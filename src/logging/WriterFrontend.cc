
#include "WriterFrontend.h"
#include "WriterBackend.h"

namespace logging  {

// Messages sent from frontend to backend (i.e., "InputMessages").

class InitMessage : public threading::InputMessage<WriterBackend>
{
public:
	InitMessage(WriterBackend* backend, const string path, const int num_fields, const Field* const *fields)
		: threading::InputMessage<WriterBackend>("Init", backend),
		path(path), num_fields(num_fields), fields(fields) { }

	virtual bool Process() { return Object()->Init(path, num_fields, fields); }

private:
	const string path;
	const int num_fields;
	const Field * const* fields;
};

class RotateMessage : public threading::InputMessage<WriterBackend>
{
public:
	RotateMessage(WriterBackend* backend, WriterFrontend* frontend, const string rotated_path, const double open,
		      const double close, const bool terminating)
		: threading::InputMessage<WriterBackend>("Rotate", backend),
		frontend(frontend),
		rotated_path(rotated_path), open(open),
		close(close), terminating(terminating) { }

	virtual bool Process() { return Object()->Rotate(frontend, rotated_path, open, close, terminating); }

private:
	WriterFrontend* frontend;
	const string rotated_path;
	const double open;
	const double close;
	const bool terminating;
};

class WriteMessage : public threading::InputMessage<WriterBackend>
{
public:
	WriteMessage(WriterBackend* backend, const int num_fields, Value **vals)
		: threading::InputMessage<WriterBackend>("Write", backend),
		num_fields(num_fields), fields(fields), vals(vals)	{}

	virtual bool Process() { return Object()->Write(num_fields, vals); }

private:
	int num_fields;
	Field* const* fields;
	Value **vals;
};

class SetBufMessage : public threading::InputMessage<WriterBackend>
{
public:
	SetBufMessage(WriterBackend* backend, const bool enabled)
		: threading::InputMessage<WriterBackend>("SetBuf", backend),
		enabled(enabled) { }

	virtual bool Process() { return Object()->SetBuf(enabled); }

private:
	const bool enabled;
};

class FlushMessage : public threading::InputMessage<WriterBackend>
{
public:
	FlushMessage(WriterBackend* backend)
		: threading::InputMessage<WriterBackend>("Flush", backend)	{}

	virtual bool Process() { return Object()->Flush(); }
};

class FinishMessage : public threading::InputMessage<WriterBackend>
{
public:
	FinishMessage(WriterBackend* backend)
		: threading::InputMessage<WriterBackend>("Finish", backend)	{}

	virtual bool Process() { return Object()->Finish(); }
};

}

// Frontend methods.

using namespace logging;

WriterFrontend::WriterFrontend(bro_int_t type)
	{
	disabled = initialized = false;
	backend = log_mgr->CreateBackend(type);

	assert(backend);
	backend->Start();
	}

WriterFrontend::~WriterFrontend()
	{
	}

void WriterFrontend::Stop()
	{
	SetDisable();
	backend->Stop();
	}

void WriterFrontend::Init(string arg_path, int arg_num_fields, const Field* const * arg_fields)
	{
	if ( disabled )
		return;

	if ( initialized )
		reporter->InternalError("writer initialize twice");

	path = arg_path;
	num_fields = arg_num_fields;
	fields = arg_fields;

	initialized = true;
	backend->SendIn(new InitMessage(backend, arg_path, arg_num_fields, arg_fields));
	}

void WriterFrontend::Write(int num_fields, Value** vals)
	{
	if ( disabled )
		return;

	backend->SendIn(new WriteMessage(backend, num_fields, vals));
	}

void WriterFrontend::SetBuf(bool enabled)
	{
	if ( disabled )
		return;

	backend->SendIn(new SetBufMessage(backend, enabled));
	}

void WriterFrontend::Flush()
	{
	if ( disabled )
		return;

	backend->SendIn(new FlushMessage(backend));
	}

void WriterFrontend::Rotate(string rotated_path, double open, double close, bool terminating)
	{
	if ( disabled )
		return;

	backend->SendIn(new RotateMessage(backend, this, rotated_path, open, close, terminating));
	}

void WriterFrontend::Finish()
	{
	if ( disabled )
		return;

	backend->SendIn(new FinishMessage(backend));
	}






