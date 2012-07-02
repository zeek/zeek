// See the file "COPYING" in the main distribution directory for copyright.

#include "Manager.h"
#include "ReaderFrontend.h"
#include "ReaderBackend.h"

#include "threading/MsgThread.h"

namespace input {

class InitMessage : public threading::InputMessage<ReaderBackend>
{
public:
	InitMessage(ReaderBackend* backend, const ReaderBackend::ReaderInfo& info,
		    const int num_fields, const threading::Field* const* fields)
		: threading::InputMessage<ReaderBackend>("Init", backend),
		info(info), num_fields(num_fields), fields(fields) { }

	virtual bool Process()
		{
		return Object()->Init(info, num_fields, fields);
		}

private:
	const ReaderBackend::ReaderInfo info;
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

void ReaderFrontend::Init(const ReaderBackend::ReaderInfo& arg_info, const int arg_num_fields,
		          const threading::Field* const* arg_fields)
	{
	if ( disabled )
		return;

	if ( initialized )
		reporter->InternalError("reader initialize twice");

	info = arg_info;
	num_fields = arg_num_fields;
	fields = arg_fields;
	initialized = true;

	backend->SendIn(new InitMessage(backend, info, num_fields, fields));
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
	if ( ! info.source.size() )
		return ty_name;

	return ty_name + "/" + info.source;
	}

}

