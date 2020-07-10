// See the file "COPYING" in the main distribution directory for copyright.

#include <broker/data.hh>

#include "util.h"
#include "threading/SerialTypes.h"

#include "Manager.h"
#include "WriterBackend.h"
#include "WriterFrontend.h"

// Messages sent from backend to frontend (i.e., "OutputMessages").

using threading::Value;
using threading::Field;

namespace logging  {

class RotationFinishedMessage final : public threading::OutputMessage<WriterFrontend>
{
public:
	RotationFinishedMessage(WriterFrontend* writer, const char* new_name, const char* old_name,
				double open, double close, bool success, bool terminating)
		: threading::OutputMessage<WriterFrontend>("RotationFinished", writer),
		new_name(copy_string(new_name)), old_name(copy_string(old_name)), open(open),
		close(close), success(success), terminating(terminating)	{ }

	~RotationFinishedMessage() override
		{
		delete [] new_name;
		delete [] old_name;
		}

	bool Process() override
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

class FlushWriteBufferMessage final : public threading::OutputMessage<WriterFrontend>
{
public:
	FlushWriteBufferMessage(WriterFrontend* writer)
		: threading::OutputMessage<WriterFrontend>("FlushWriteBuffer", writer)	{}

	bool Process() override	{ Object()->FlushWriteBuffer(); return true; }
};

class DisableMessage final : public threading::OutputMessage<WriterFrontend>
{
public:
	DisableMessage(WriterFrontend* writer)
		: threading::OutputMessage<WriterFrontend>("Disable", writer)	{}

	bool Process() override	{ Object()->SetDisable(); return true; }
};

}

// Backend methods.

using namespace logging;

broker::data WriterBackend::WriterInfo::ToBroker() const
	{
	auto t = broker::table();

	for ( config_map::const_iterator i = config.begin(); i != config.end(); ++i )
		{
		auto key = std::string(i->first);
		auto value = std::string(i->second);
		t.insert(std::make_pair(key, value));
		}

	auto bppf = post_proc_func ? post_proc_func : "";

	return broker::vector({path, rotation_base, rotation_interval, network_time, std::move(t), bppf});
	}

bool WriterBackend::WriterInfo::FromBroker(broker::data d)
	{
	if ( ! caf::holds_alternative<broker::vector>(d) )
		return false;

	auto v = caf::get<broker::vector>(d);
	auto bpath = caf::get_if<std::string>(&v[0]);
	auto brotation_base = caf::get_if<double>(&v[1]);
	auto brotation_interval = caf::get_if<double>(&v[2]);
	auto bnetwork_time = caf::get_if<double>(&v[3]);
	auto bconfig = caf::get_if<broker::table>(&v[4]);
	auto bppf = caf::get_if<std::string>(&v[5]);

	if ( ! (bpath && brotation_base && brotation_interval && bnetwork_time && bconfig && bppf) )
		return false;

	path = copy_string(bpath->c_str());
	post_proc_func = copy_string(bppf->c_str());
	rotation_base = *brotation_base;
	rotation_interval = *brotation_interval;
	network_time = *bnetwork_time;

	for ( auto i : *bconfig )
		{
		auto k = caf::get_if<std::string>(&i.first);
		auto v = caf::get_if<std::string>(&i.second);

		if ( ! (k && v) )
			return false;

		auto p = std::make_pair(copy_string(k->c_str()), copy_string(v->c_str()));
		config.insert(p);
		}

	return true;
	}

WriterBackend::WriterBackend(WriterFrontend* arg_frontend) : MsgThread()
	{
	num_fields = 0;
	fields = nullptr;
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
	SendOut(new RotationFinishedMessage(frontend, nullptr, nullptr, 0, 0, false, false));
	return true;
	}

void WriterBackend::DisableFrontend()
	{
	SendOut(new DisableMessage(frontend));
	}

bool WriterBackend::Init(int arg_num_fields, const Field* const* arg_fields)
	{
	SetOSName(Fmt("zk.%s", Name()));
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
				const char* msg = Fmt("Field #%d type doesn't match in WriterBackend::Write() (%d vs. %d)",
						      i, vals[j][i]->type, fields[i]->type);
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
