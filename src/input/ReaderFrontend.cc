// See the file "COPYING" in the main distribution directory for copyright.

#include "Manager.h"
#include "ReaderFrontend.h"
#include "ReaderBackend.h"
#include "threading/MsgThread.h"

// FIXME: cleanup of disabled inputreaders is missing. we need this, because stuff can e.g. fail in init and might never be removed afterwards.

namespace input {

class InitMessage : public threading::InputMessage<ReaderBackend>
{
public:
	InitMessage(ReaderBackend* backend, const string source)
		: threading::InputMessage<ReaderBackend>("Init", backend),
		source(source) { }

	virtual bool Process() { return Object()->Init(source); }

private:
	const string source;
};

class UpdateMessage : public threading::InputMessage<ReaderBackend>
{
public:
	UpdateMessage(ReaderBackend* backend)
		: threading::InputMessage<ReaderBackend>("Update", backend)
		 { }

	virtual bool Process() { return Object()->Update(); }
};

class FinishMessage : public threading::InputMessage<ReaderBackend>
{
public:
	FinishMessage(ReaderBackend* backend)
		: threading::InputMessage<ReaderBackend>("Finish", backend)
		 { }

	virtual bool Process() { Object()->Finish(); return true; }
};

class AddFilterMessage : public threading::InputMessage<ReaderBackend>
{
public:
	AddFilterMessage(ReaderBackend* backend, const int id, const int num_fields, const threading::Field* const* fields)
		: threading::InputMessage<ReaderBackend>("AddFilter", backend),
		id(id), num_fields(num_fields), fields(fields) { }

	virtual bool Process() { return Object()->AddFilter(id, num_fields, fields); }

private:
	const int id;
	const int num_fields;
       	const threading::Field* const* fields;
};

class RemoveFilterMessage : public threading::InputMessage<ReaderBackend>
{
public:
	RemoveFilterMessage(ReaderBackend* backend, const int id)
		: threading::InputMessage<ReaderBackend>("RemoveFilter", backend),
		id(id) { }

	virtual bool Process() { return Object()->RemoveFilter(id); }

private:
	const int id;
};


ReaderFrontend::ReaderFrontend(bro_int_t type) {
	disabled = initialized = false;
	ty_name = "<not set>";
	backend = input_mgr->CreateBackend(this, type);

	assert(backend);
	backend->Start();
}

ReaderFrontend::~ReaderFrontend() {
}

void ReaderFrontend::Init(string arg_source) {
	if ( disabled )
		return;

	if ( initialized )
		reporter->InternalError("writer initialize twice");

	source = arg_source;
	initialized = true;

	backend->SendIn(new InitMessage(backend, arg_source));
} 

void ReaderFrontend::Update() {
	if ( disabled ) 
		return;

	backend->SendIn(new UpdateMessage(backend));
}

void ReaderFrontend::Finish() {
	if ( disabled ) 
		return;

	backend->SendIn(new FinishMessage(backend));
}

void ReaderFrontend::AddFilter(const int id, const int arg_num_fields, const threading::Field* const* fields) {
	if ( disabled ) 
		return;

	backend->SendIn(new AddFilterMessage(backend, id, arg_num_fields, fields));
}

void ReaderFrontend::RemoveFilter(const int id) {
	if ( disabled ) 
		return;

	backend->SendIn(new RemoveFilterMessage(backend, id));
}

string ReaderFrontend::Name() const
{
	if ( source.size() )
		return ty_name;

	return ty_name + "/" + source;
}

}


