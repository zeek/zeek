// See the file "COPYING" in the main distribution directory for copyright.

#include "util.h"
#include "threading/SerialTypes.h"

#include "Manager.h"
#include "WriterBackend.h"
#include "WriterFrontend.h"

// Messages sent from backend to frontend (i.e., "OutputMessages").

using threading::Value;
using threading::Field;

namespace logging  {

class RotationFinishedMessage : public threading::OutputMessage<WriterFrontend>
{
public:
	RotationFinishedMessage(WriterFrontend* writer, const char* new_name, const char* old_name,
				double open, double close, bool success, bool terminating)
		: threading::OutputMessage<WriterFrontend>("RotationFinished", writer),
		new_name(copy_string(new_name)), old_name(copy_string(old_name)), open(open),
		close(close), success(success), terminating(terminating)	{ }

	virtual ~RotationFinishedMessage()
		{
		delete [] new_name;
		delete [] old_name;
		}

	virtual bool Process()
		{
		return log_mgr->FinishedRotation(Object(), new_name, old_name, open, close, success, terminating);
		}

private:
        const char* new_name;
        const char* old_name;
        double open;
        double close;
	bool success;
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

bool WriterBackend::WriterInfo::Read(SerializationFormat* fmt)
	{
	int size;

	string tmp_path;

	if ( ! (fmt->Read(&tmp_path, "path") &&
		fmt->Read(&rotation_base, "rotation_base") &&
		fmt->Read(&rotation_interval, "rotation_interval") &&
		fmt->Read(&network_time, "network_time") &&
		fmt->Read(&size, "config_size")) )
		return false;

	path = copy_string(tmp_path.c_str());

	config.clear();

	while ( size )
		{
		string value;
		string key;

		if ( ! (fmt->Read(&value, "config-value") && fmt->Read(&value, "config-key")) )
			return false;

		config.insert(std::make_pair(copy_string(value.c_str()), copy_string(key.c_str())));
		}

	return true;
	}


bool WriterBackend::WriterInfo::Write(SerializationFormat* fmt) const
	{
	int size = config.size();

	if ( ! (fmt->Write(path, "path") &&
		fmt->Write(rotation_base, "rotation_base") &&
		fmt->Write(rotation_interval, "rotation_interval") &&
		fmt->Write(network_time, "network_time") &&
		fmt->Write(size, "config_size")) )
		return false;

	for ( config_map::const_iterator i = config.begin(); i != config.end(); ++i )
		{
		if ( ! (fmt->Write(i->first, "config-value") && fmt->Write(i->second, "config-key")) )
			return false;
		}

	return true;
	}

WriterBackend::WriterBackend(WriterFrontend* arg_frontend) : MsgThread()
	{
	num_fields = 0;
	fields = 0;
	buffering = true;
	frontend = arg_frontend;
	info = new WriterInfo(frontend->Info());
	rotation_counter = 0;

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

	delete info;
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

bool WriterBackend::FinishedRotation(const char* new_name, const char* old_name,
				     double open, double close, bool terminating)
	{
	--rotation_counter;
	SendOut(new RotationFinishedMessage(frontend, new_name, old_name, open, close, true, terminating));
	return true;
	}

bool WriterBackend::FinishedRotation()
	{
	--rotation_counter;
	SendOut(new RotationFinishedMessage(frontend, 0, 0, 0, 0, false, false));
	return true;
	}

void WriterBackend::DisableFrontend()
	{
	SendOut(new DisableMessage(frontend));
	}

bool WriterBackend::Init(int arg_num_fields, const Field* const* arg_fields)
	{
	SetOSName(Fmt("bro: %s", Name()));
	num_fields = arg_num_fields;
	fields = arg_fields;

	if ( Failed() )
		return true;

	if ( ! DoInit(*info, arg_num_fields, arg_fields) )
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

	// Double-check all the types match.
	for ( int j = 0; j < num_writes; j++ )
		{
		for ( int i = 0; i < num_fields; ++i )
			{
			if ( vals[j][i]->type != fields[i]->type )
				{
#ifdef DEBUG
				const char* msg = Fmt("Field type doesn't match in WriterBackend::Write() (%d vs. %d)",
						      vals[j][i]->type, fields[i]->type);
				Debug(DBG_LOGGING, msg);
#endif
				DisableFrontend();
				DeleteVals(num_writes, vals);
				return false;
				}
			}
		}

	bool success = true;

	if ( ! Failed() )
		{
		for ( int j = 0; j < num_writes; j++ )
			{
			success = DoWrite(num_fields, fields, vals[j]);

			if ( ! success )
				break;
			}
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

	if ( Failed() )
		return true;

	buffering = enabled;

	if ( ! DoSetBuf(enabled) )
		{
		DisableFrontend();
		return false;
		}

	return true;
	}

bool WriterBackend::Rotate(const char* rotated_path, double open,
			   double close, bool terminating)
	{
	if ( Failed() )
		return true;

	rotation_counter = 1;

	if ( ! DoRotate(rotated_path, open, close, terminating) )
		{
		DisableFrontend();
		return false;
		}

	// Insurance against broken writers.
	if ( rotation_counter > 0 )
		InternalError(Fmt("writer %s did not call FinishedRotation() in DoRotation()", Name()));

	if ( rotation_counter < 0 )
		InternalError(Fmt("writer %s called FinishedRotation() more than once in DoRotation()", Name()));

	return true;
	}

bool WriterBackend::Flush(double network_time)
	{
	if ( Failed() )
		return true;

	if ( ! DoFlush(network_time) )
		{
		DisableFrontend();
		return false;
		}

	return true;
	}

bool WriterBackend::OnFinish(double network_time)
	{
	if ( Failed() )
		return true;

	return DoFinish(network_time);
	}

bool WriterBackend::OnHeartbeat(double network_time, double current_time)
	{
	if ( Failed() )
		return true;

	SendOut(new FlushWriteBufferMessage(frontend));
	return DoHeartbeat(network_time, current_time);
	}
