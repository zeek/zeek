// See the file "COPYING" in the main distribution directory for copyright.

#include "ReaderBackend.h"
#include "ReaderFrontend.h"
#include "Manager.h"

using threading::Value;
using threading::Field;

namespace input {

class PutMessage : public threading::OutputMessage<ReaderFrontend> {
public:
	PutMessage(ReaderFrontend* reader, int id, Value* *val)
		: threading::OutputMessage<ReaderFrontend>("Put", reader),
		id(id), val(val) {}

	virtual bool Process() {
		input_mgr->Put(Object(), id, val);
		return true;
	}

private:
	int id;
	Value* *val;
};

class DeleteMessage : public threading::OutputMessage<ReaderFrontend> {
public:
	DeleteMessage(ReaderFrontend* reader, int id, Value* *val)
		: threading::OutputMessage<ReaderFrontend>("Delete", reader),
		id(id), val(val) {}

	virtual bool Process() {
		return input_mgr->Delete(Object(), id, val);
	}

private:
	int id;
	Value* *val;
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
	SendEventMessage(ReaderFrontend* reader, const string& name, const int num_vals, Value* *val)
		: threading::OutputMessage<ReaderFrontend>("SendEvent", reader),
		name(name), num_vals(num_vals), val(val) {}

	virtual bool Process() {
		return input_mgr->SendEvent(name, num_vals, val);
	}

private:
	const string name;
	const int num_vals;
	Value* *val;
};

class SendEntryMessage : public threading::OutputMessage<ReaderFrontend> {
public:
	SendEntryMessage(ReaderFrontend* reader, const int id, Value* *val)
		: threading::OutputMessage<ReaderFrontend>("SendEntry", reader),
		id(id), val(val) { }

	virtual bool Process() {
		input_mgr->SendEntry(Object(), id, val);
		return true;
	}

private:
	const int id;
	Value* *val;
};

class EndCurrentSendMessage : public threading::OutputMessage<ReaderFrontend> {
public:
	EndCurrentSendMessage(ReaderFrontend* reader, const int id)
		: threading::OutputMessage<ReaderFrontend>("EndCurrentSend", reader),
		id(id) {}

	virtual bool Process() {
		input_mgr->EndCurrentSend(Object(), id);
		return true;
	}

private:
	const int id;
};

class FilterRemovedMessage : public threading::OutputMessage<ReaderFrontend> {
public:
	FilterRemovedMessage(ReaderFrontend* reader, const int id)
		: threading::OutputMessage<ReaderFrontend>("FilterRemoved", reader),
		id(id) {}

	virtual bool Process() {
		return input_mgr->RemoveFilterContinuation(Object(), id);
	}

private:
	const int id;
};

class ReaderFinishedMessage : public threading::OutputMessage<ReaderFrontend> {
public:
	ReaderFinishedMessage(ReaderFrontend* reader)
		: threading::OutputMessage<ReaderFrontend>("ReaderFinished", reader) {}

	virtual bool Process() {
		return input_mgr->RemoveStreamContinuation(Object());
	}

private:
};


class DisableMessage : public threading::OutputMessage<ReaderFrontend>
{
public:
        DisableMessage(ReaderFrontend* writer)
		: threading::OutputMessage<ReaderFrontend>("Disable", writer)	{}

	virtual bool Process()	{ Object()->SetDisable(); return true; }
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

void ReaderBackend::Put(int id, Value* *val) 
{
	SendOut(new PutMessage(frontend, id, val));
}

void ReaderBackend::Delete(int id, Value* *val) 
{
	SendOut(new DeleteMessage(frontend, id, val));
}

void ReaderBackend::Clear(int id) 
{
	SendOut(new ClearMessage(frontend, id));
}

void ReaderBackend::SendEvent(const string& name, const int num_vals, Value* *vals) 
{
	SendOut(new SendEventMessage(frontend, name, num_vals, vals));
} 

void ReaderBackend::EndCurrentSend(int id) 
{
	SendOut(new EndCurrentSendMessage(frontend, id));
}

void ReaderBackend::SendEntry(int id, Value* *vals)
{
	SendOut(new SendEntryMessage(frontend, id, vals));
}

bool ReaderBackend::Init(string arg_source, int mode, bool arg_autostart) 
{
	source = arg_source;
	autostart = arg_autostart;
	SetName("InputReader/"+source);

	// disable if DoInit returns error.
	disabled = !DoInit(arg_source, mode);

	if ( disabled ) {
		Error("Init failed");
		DisableFrontend();
	}

	return !disabled;
}

bool ReaderBackend::StartReading() {
	if ( disabled ) 
		return false;

	int success = DoStartReading();
	
	if ( success == false ) {
		DisableFrontend();
	} 

	return success;
}

bool ReaderBackend::AddFilter(int id, int arg_num_fields,
					   const Field* const * arg_fields) 
{
	if ( disabled ) 
		return false;

	bool success = DoAddFilter(id, arg_num_fields, arg_fields);
	if ( success && autostart) {
		autostart = false;
		return StartReading();
	}
	return success;
}

bool ReaderBackend::RemoveFilter(int id) 
{
	if ( disabled ) 
		return false;

	bool success = DoRemoveFilter(id);
	SendOut(new FilterRemovedMessage(frontend, id));
	return success; // yes, I know, noone reads this.
}

void ReaderBackend::Finish() 
{
	DoFinish();
	disabled = true;
	DisableFrontend();
	SendOut(new ReaderFinishedMessage(frontend));
}

bool ReaderBackend::Update() 
{
	if ( disabled ) 
		return false;

	bool success = DoUpdate();
	if ( !success ) {
		DisableFrontend();
	}

	return success;
}

void ReaderBackend::DisableFrontend()
{
	disabled = true; // we also set disabled here, because there still may be other messages queued and we will dutifully ignore these from now
	SendOut(new DisableMessage(frontend));
}

bool ReaderBackend::DoHeartbeat(double network_time, double current_time)
{
	MsgThread::DoHeartbeat(network_time, current_time);

	return true;
}

TransportProto ReaderBackend::StringToProto(const string &proto) {
	if ( proto == "unknown" ) {
		return TRANSPORT_UNKNOWN;
	} else if ( proto == "tcp" ) {
		return TRANSPORT_TCP;
	} else if ( proto == "udp" ) {
		return TRANSPORT_UDP;
	} else if ( proto == "icmp" ) {
		return TRANSPORT_ICMP;
	}

	Error(Fmt("Tried to parse invalid/unknown protocol: %s", proto.c_str()));

	return TRANSPORT_UNKNOWN;
}


// more or less verbose copy from IPAddr.cc -- which uses reporter
Value::addr_t ReaderBackend::StringToAddr(const string &s) {
	Value::addr_t val;

	if ( s.find(':') == std::string::npos ) // IPv4.
		{
		val.family = IPv4;

		if ( inet_aton(s.c_str(), &(val.in.in4)) <= 0 ) {
			Error(Fmt("Bad addres: %s", s.c_str()));
			memset(&val.in.in4.s_addr, 0, sizeof(val.in.in4.s_addr));
		}


		}
	else
		{
		val.family = IPv6;
		if ( inet_pton(AF_INET6, s.c_str(), val.in.in6.s6_addr) <=0 )
			{
			Error(Fmt("Bad IP address: %s", s.c_str()));
			memset(val.in.in6.s6_addr, 0, sizeof(val.in.in6.s6_addr));
			}
		}

	return val;
}

}
