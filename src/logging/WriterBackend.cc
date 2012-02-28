// See the file "COPYING" in the main distribution directory for copyright.

#include "util.h"
#include "threading/SerialTypes.h"

#include "WriterBackend.h"
#include "WriterFrontend.h"

// Messages sent from backend to frontend (i.e., "OutputMessages").

using threading::Value;
using threading::Field;

namespace logging  {

class RotationFinishedMessage : public threading::OutputMessage<WriterFrontend>
{
public:
        RotationFinishedMessage(WriterFrontend* writer, string new_name, string old_name,
				double open, double close, bool terminating)
		: threading::OutputMessage<WriterFrontend>("RotationFinished", writer),
		new_name(new_name), old_name(old_name), open(open),
		close(close), terminating(terminating)	{ }

	virtual bool Process()
		{
		return log_mgr->FinishedRotation(Object(), new_name, old_name, open, close, terminating);
		}

private:
        string new_name;
        string old_name;
        double open;
        double close;
        bool terminating;
};

class FlushWriteBufferMessage : public threading::OutputMessage<WriterFrontend>
{
public:
        FlushWriteBufferMessage(WriterFrontend* writer)
		: threading::OutputMessage<WriterFrontend>("FlushWriteBuffer", writer)	{}

	virtual bool Process()	{ Object()->FlushWriteBuffer(); return true; }
};

class DisableMessage : public threading::OutputMessage<WriterFrontend>
{
public:
        DisableMessage(WriterFrontend* writer)
		: threading::OutputMessage<WriterFrontend>("Disable", writer)	{}

	virtual bool Process()	{ Object()->SetDisable(); return true; }
};

}

// Backend methods.

using namespace logging;

WriterBackend::WriterBackend(WriterFrontend* arg_frontend) : MsgThread()
	{
	path = "<path not yet set>";
	num_fields = 0;
	fields = 0;
	buffering = true;
	frontend = arg_frontend;

	SetName(frontend->Name());
	}

WriterBackend::~WriterBackend()
	{
	if ( fields )
		{
		for(int i = 0; i < num_fields; ++i)
			delete fields[i];

		delete [] fields;
		}
	}

void WriterBackend::DeleteVals(int num_writes, Value*** vals)
	{
	for ( int j = 0; j < num_writes; ++j )
		{
		// Note this code is duplicated in Manager::DeleteVals().
		for ( int i = 0; i < num_fields; i++ )
			delete vals[j][i];

		delete [] vals[j];
		}

	delete [] vals;
	}

bool WriterBackend::FinishedRotation(string new_name, string old_name,
				     double open, double close, bool terminating)
	{
	SendOut(new RotationFinishedMessage(frontend, new_name, old_name, open, close, terminating));
	return true;
	}

void WriterBackend::DisableFrontend()
	{
	SendOut(new DisableMessage(frontend));
	}

bool WriterBackend::Init(string arg_path, int arg_num_fields, const Field* const*  arg_fields)
	{
	path = arg_path;
	num_fields = arg_num_fields;
	fields = arg_fields;

	string name = Fmt("%s/%s", path.c_str(), frontend->Name().c_str());

	SetName(name);

	if ( ! DoInit(arg_path, arg_num_fields, arg_fields) )
		{
		DisableFrontend();
		return false;
		}

	return true;
	}

bool WriterBackend::Write(int arg_num_fields, int num_writes, Value*** vals)
	{
	// Double-check that the arguments match. If we get this from remote,
	// something might be mixed up.
	if ( num_fields != arg_num_fields )
		{

#ifdef DEBUG
		const char* msg = Fmt("Number of fields don't match in WriterBackend::Write() (%d vs. %d)",
				      arg_num_fields, num_fields);
		Debug(DBG_LOGGING, msg);
#endif

		DeleteVals(num_writes, vals);
		DisableFrontend();
		return false;
		}

#ifdef DEBUG
	// Double-check all the types match.
	for ( int j = 0; j < num_writes; j++ )
		{
		for ( int i = 0; i < num_fields; ++i )
			{
			if ( vals[j][i]->type != fields[i]->type )
				{
				const char* msg = Fmt("Field type doesn't match in WriterBackend::Write() (%d vs. %d)",
						      vals[j][i]->type, fields[i]->type);
				Debug(DBG_LOGGING, msg);

				DisableFrontend();
				DeleteVals(num_writes, vals);
				return false;
				}
			}
		}
#endif

	bool success = true;

	for ( int j = 0; j < num_writes; j++ )
		{
		success = DoWrite(num_fields, fields, vals[j]);

		if ( ! success )
			break;
		}

	DeleteVals(num_writes, vals);

	if ( ! success )
		DisableFrontend();

	return success;
	}

bool WriterBackend::SetBuf(bool enabled)
	{
	if ( enabled == buffering )
		// No change.
		return true;

	buffering = enabled;

	if ( ! DoSetBuf(enabled) )
		{
		DisableFrontend();
		return false;
		}

	return true;
	}

bool WriterBackend::Rotate(string rotated_path, double open,
			   double close, bool terminating)
	{
	if ( ! DoRotate(rotated_path, open, close, terminating) )
		{
		DisableFrontend();
		return false;
		}

	return true;
	}

bool WriterBackend::Flush()
	{
	if ( ! DoFlush() )
		{
		DisableFrontend();
		return false;
		}

	return true;
	}

bool WriterBackend::Finish()
	{
	if ( ! DoFlush() )
		{
		DisableFrontend();
		return false;
		}

	return true;
	}

bool WriterBackend::DoHeartbeat(double network_time, double current_time)
	{
	MsgThread::DoHeartbeat(network_time, current_time);

	SendOut(new FlushWriteBufferMessage(frontend));

	return true;
	}

string WriterBackend::Render(const threading::Value::addr_t& addr) const
	{
	if ( addr.family == IPv4 )
		{
		char s[INET_ADDRSTRLEN];

		if ( inet_ntop(AF_INET, &addr.in.in4, s, INET_ADDRSTRLEN) == NULL )
			return "<bad IPv4 address conversion>";
		else
			return s;
		}
	else
		{
		char s[INET6_ADDRSTRLEN];

		if ( inet_ntop(AF_INET6, &addr.in.in6, s, INET6_ADDRSTRLEN) == NULL )
			return "<bad IPv6 address conversion>";
		else
			return s;
		}
	}

string WriterBackend::Render(const threading::Value::subnet_t& subnet) const
	{
	char l[16];

	if ( subnet.prefix.family == IPv4 )
		modp_uitoa10(subnet.length - 96, l);
	else
		modp_uitoa10(subnet.length, l);

	string s = Render(subnet.prefix) + "/" + l;

	return s;
	}


