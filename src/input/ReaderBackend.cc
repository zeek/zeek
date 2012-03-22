// See the file "COPYING" in the main distribution directory for copyright.

#include "ReaderBackend.h"
#include "ReaderFrontend.h"
#include "Manager.h"

using threading::Value;
using threading::Field;

namespace input {

class PutMessage : public threading::OutputMessage<ReaderFrontend> {
public:
	PutMessage(ReaderFrontend* reader, Value* *val)
		: threading::OutputMessage<ReaderFrontend>("Put", reader),
		val(val) {}

	virtual bool Process() {
		input_mgr->Put(Object(), val);
		return true;
	}

private:
	Value* *val;
};

class DeleteMessage : public threading::OutputMessage<ReaderFrontend> {
public:
	DeleteMessage(ReaderFrontend* reader, Value* *val)
		: threading::OutputMessage<ReaderFrontend>("Delete", reader),
		val(val) {}

	virtual bool Process() {
		return input_mgr->Delete(Object(), val);
	}

private:
	Value* *val;
};

class ClearMessage : public threading::OutputMessage<ReaderFrontend> {
public:
	ClearMessage(ReaderFrontend* reader)
		: threading::OutputMessage<ReaderFrontend>("Clear", reader) {}

	virtual bool Process() {
		input_mgr->Clear(Object());
		return true;
	}

private:
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
	SendEntryMessage(ReaderFrontend* reader, Value* *val)
		: threading::OutputMessage<ReaderFrontend>("SendEntry", reader),
		val(val) { }

	virtual bool Process() {
		input_mgr->SendEntry(Object(), val);
		return true;
	}

private:
	Value* *val;
};

class EndCurrentSendMessage : public threading::OutputMessage<ReaderFrontend> {
public:
	EndCurrentSendMessage(ReaderFrontend* reader)
		: threading::OutputMessage<ReaderFrontend>("EndCurrentSend", reader) {}

	virtual bool Process() {
		input_mgr->EndCurrentSend(Object());
		return true;
	}

private:
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

void ReaderBackend::Put(Value* *val) 
{
	SendOut(new PutMessage(frontend, val));
}

void ReaderBackend::Delete(Value* *val) 
{
	SendOut(new DeleteMessage(frontend, val));
}

void ReaderBackend::Clear() 
{
	SendOut(new ClearMessage(frontend));
}

void ReaderBackend::SendEvent(const string& name, const int num_vals, Value* *vals) 
{
	SendOut(new SendEventMessage(frontend, name, num_vals, vals));
} 

void ReaderBackend::EndCurrentSend() 
{
	SendOut(new EndCurrentSendMessage(frontend));
}

void ReaderBackend::SendEntry(Value* *vals)
{
	SendOut(new SendEntryMessage(frontend, vals));
}

bool ReaderBackend::Init(string arg_source, int mode, const int arg_num_fields, const threading::Field* const* arg_fields) 
{
	source = arg_source;
	SetName("InputReader/"+source);

	// disable if DoInit returns error.
	int success = DoInit(arg_source, mode, arg_num_fields, arg_fields);

	if ( !success ) {
		Error("Init failed");
		DisableFrontend();
	}

	disabled = !success;

	return success;
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
