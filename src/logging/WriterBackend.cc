// See the file "COPYING" in the main distribution directory for copyright.

#include "util.h"

#include "WriterBackend.h"
#include "WriterFrontend.h"

// Messages sent from backend to frontend (i.e., "OutputMessages").

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

WriterBackend::WriterBackend(const string& name) : MsgThread(name)
	{
	path = "<not set>";
	num_fields = 0;
	fields = 0;
	buffering = true;
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

void WriterBackend::DeleteVals(Value** vals)
	{
	// Note this code is duplicated in Manager::DeleteVals().
	for ( int i = 0; i < num_fields; i++ )
		delete vals[i];

	delete [] vals;
	}

bool WriterBackend::FinishedRotation(WriterFrontend* writer, string new_name, string old_name,
				     double open, double close, bool terminating)
	{
	SendOut(new RotationFinishedMessage(writer, new_name, old_name, open, close, terminating));
	return true;
	}

bool WriterBackend::Init(string arg_path, int arg_num_fields,
		     const Field* const * arg_fields)
	{
	path = arg_path;
	num_fields = arg_num_fields;
	fields = arg_fields;

	if ( ! DoInit(arg_path, arg_num_fields, arg_fields) )
		return false;

	return true;
	}

bool WriterBackend::Write(int arg_num_fields, Value** vals)
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

		DeleteVals(vals);
		return false;
		}

	for ( int i = 0; i < num_fields; ++i )
		{
		if ( vals[i]->type != fields[i]->type )
			{
#ifdef DEBUG
			const char* msg = Fmt("Field type doesn't match in WriterBackend::Write() (%d vs. %d)",
					      vals[i]->type, fields[i]->type);
			Debug(DBG_LOGGING, msg);
#endif

			DeleteVals(vals);
			return false;
			}
		}

	bool result = DoWrite(num_fields, fields, vals);

	DeleteVals(vals);

	return result;
	}

bool WriterBackend::SetBuf(bool enabled)
	{
	if ( enabled == buffering )
		// No change.
		return true;

	buffering = enabled;

	return DoSetBuf(enabled);
	}

bool WriterBackend::Rotate(WriterFrontend* writer, string rotated_path,
			   double open, double close, bool terminating)
	{
	return DoRotate(writer, rotated_path, open, close, terminating);
	}

bool WriterBackend::Flush()
	{
	return DoFlush();
	}

bool WriterBackend::Finish()
	{
	return DoFinish();
	}
