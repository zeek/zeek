// See the file "COPYING" in the main distribution directory for copyright.

#include "Manager.h"
#include "ReaderFrontend.h"
#include "ReaderBackend.h"

#include "threading/MsgThread.h"

namespace input {

class InitMessage : public threading::InputMessage<ReaderBackend>
{
public:
	InitMessage(ReaderBackend* backend, const string source, ReaderMode mode,
		    const int num_fields, const threading::Field* const* fields)
		: threading::InputMessage<ReaderBackend>("Init", backend),
		source(source), mode(mode), num_fields(num_fields), fields(fields) { }

	virtual bool Process()
		{
		return Object()->Init(source, mode, num_fields, fields);
		}

private:
	const string source;
	const ReaderMode mode;
	const int num_fields;
	const threading::Field* const* fields;
};

class UpdateMessage : public threading::InputMessage<ReaderBackend>
{
public:
	UpdateMessage(ReaderBackend* backend)
		: threading::InputMessage<ReaderBackend>("Update", backend)
		 { }

	virtual bool Process() { return Object()->Update(); }
};

class CloseMessage : public threading::InputMessage<ReaderBackend>
{
public:
	CloseMessage(ReaderBackend* backend)
		: threading::InputMessage<ReaderBackend>("Close", backend)
		 { }

	virtual bool Process() { Object()->Close(); return true; }
};


ReaderFrontend::ReaderFrontend(bro_int_t type)
	{
	disabled = initialized = false;
	ty_name = "<not set>";
	backend = input_mgr->CreateBackend(this, type);

	assert(backend);
	backend->Start();
	}

ReaderFrontend::~ReaderFrontend()
	{
	}

void ReaderFrontend::Init(string arg_source, ReaderMode mode, const int num_fields,
		          const threading::Field* const* fields)
	{
	if ( disabled )
		return;

	if ( initialized )
		reporter->InternalError("reader initialize twice");

	source = arg_source;
	initialized = true;

	backend->SendIn(new InitMessage(backend, arg_source, mode, num_fields, fields));
	}

void ReaderFrontend::Update()
	{
	if ( disabled )
		return;

	if ( ! initialized )
		{
		reporter->Error("Tried to call update on uninitialized reader");
		return;
		}

	backend->SendIn(new UpdateMessage(backend));
	}

void ReaderFrontend::Close()
	{
	if ( disabled )
		return;

	if ( ! initialized )
		{
		reporter->Error("Tried to call finish on uninitialized reader");
		return;
		}

	disabled = true;
	backend->SendIn(new CloseMessage(backend));
	}

string ReaderFrontend::Name() const
	{
	if ( source.size() )
		return ty_name;

	return ty_name + "/" + source;
	}

}

