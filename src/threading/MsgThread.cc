
#include "DebugLogger.h"

#include "MsgThread.h"
#include "Manager.h"

using namespace threading;

namespace threading  {

////// Messages.

// Signals child thread to terminate. This is actually a no-op; its only
// purpose is unblock the current read operation so that the child's Run()
// methods can check the termination status.
class TerminateMessage : public InputMessage<MsgThread>
{
public:
	TerminateMessage(MsgThread* thread) : InputMessage<MsgThread>("Terminate", thread)	{ }

	virtual bool Process()	{ return true; }
};

/// Sends a heartbeat to the child thread.
class HeartbeatMessage : public InputMessage<MsgThread>
{
public:
	HeartbeatMessage(MsgThread* thread, double arg_network_time, double arg_current_time)
		: InputMessage<MsgThread>("Heartbeat", thread)
		{ network_time = arg_network_time; current_time = arg_current_time; }

	virtual bool Process()	{ return Object()->DoHeartbeat(network_time, current_time); }

private:
	double network_time;
	double current_time;
};

// A message from the child to be passed on to the Reporter.
class ReporterMessage : public OutputMessage<MsgThread>
{
public:
	enum Type {
		INFO, WARNING, ERROR, FATAL_ERROR, FATAL_ERROR_WITH_CORE,
		INTERNAL_WARNING, INTERNAL_ERROR
	};

	ReporterMessage(Type arg_type, MsgThread* thread, const string& arg_msg)
		: OutputMessage<MsgThread>("ReporterMessage", thread)
		{ type = arg_type; msg = arg_msg; }

	virtual bool Process();

private:
	string msg;
	Type type;
};

#ifdef DEBUG
// A debug message from the child to be passed on to the DebugLogger.
class DebugMessage : public OutputMessage<MsgThread>
{
public:
	DebugMessage(DebugStream arg_stream, MsgThread* thread, const string& arg_msg)
		: OutputMessage<MsgThread>("DebugMessage", thread)
		{ stream = arg_stream; msg = arg_msg; }

	virtual bool Process()
		{
		string s = Object()->Name() + ": " + msg;
		debug_logger.Log(stream, "%s", s.c_str());
		return true;
		}
private:
	string msg;
	DebugStream stream;
};
#endif

}

////// Methods.

Message::~Message()
	{
	}

bool ReporterMessage::Process()
	{
	string s = Object()->Name() + ": " + msg;
	const char* cmsg = s.c_str();

	switch ( type ) {

	case INFO:
		reporter->Info("%s", cmsg);
		break;

	case WARNING:
		reporter->Warning("%s", cmsg);
		break;

	case ERROR:
		reporter->Error("%s", cmsg);
		break;

	case FATAL_ERROR:
		reporter->FatalError("%s", cmsg);
		break;

	case FATAL_ERROR_WITH_CORE:
		reporter->FatalErrorWithCore("%s", cmsg);
		break;

	case INTERNAL_WARNING:
		reporter->InternalWarning("%s", cmsg);
		break;

	case INTERNAL_ERROR :
		reporter->InternalError("%s", cmsg);
		break;

	default:
		reporter->InternalError("unknown ReporterMessage type %d", type);
	}

	return true;
	}

MsgThread::MsgThread() : BasicThread()
	{
	cnt_sent_in = cnt_sent_out = 0;
	thread_mgr->AddMsgThread(this);
	}

void MsgThread::OnStop()
	{
	// This is to unblock the current queue read operation.
	SendIn(new TerminateMessage(this), true);
	}

void MsgThread::Heartbeat()
	{
	SendIn(new HeartbeatMessage(this, network_time, current_time()));
	}

bool MsgThread::DoHeartbeat(double network_time, double current_time)
	{
	string n = Name();

	n = Fmt("bro: %s (%" PRIu64 "/%" PRIu64 ")", n.c_str(),
		cnt_sent_in - queue_in.Size(),
		cnt_sent_out - queue_out.Size());

	SetOSName(n.c_str());

	return true;
	}

void MsgThread::Info(const char* msg)
	{
	SendOut(new ReporterMessage(ReporterMessage::INFO, this, msg));
	}

void MsgThread::Warning(const char* msg)
	{
	SendOut(new ReporterMessage(ReporterMessage::WARNING, this, msg));
	}

void MsgThread::Error(const char* msg)
	{
	SendOut(new ReporterMessage(ReporterMessage::ERROR, this, msg));
	}

void MsgThread::FatalError(const char* msg)
	{
	SendOut(new ReporterMessage(ReporterMessage::FATAL_ERROR, this, msg));
	}

void MsgThread::FatalErrorWithCore(const char* msg)
	{
	SendOut(new ReporterMessage(ReporterMessage::FATAL_ERROR_WITH_CORE, this, msg));
	}

void MsgThread::InternalWarning(const char* msg)
	{
	SendOut(new ReporterMessage(ReporterMessage::INTERNAL_WARNING, this, msg));
	}

void MsgThread::InternalError(const char* msg)
	{
	SendOut(new ReporterMessage(ReporterMessage::INTERNAL_ERROR, this, msg));
	}

#ifdef DEBUG

void MsgThread::Debug(DebugStream stream, const char* msg)
	{
	SendOut(new DebugMessage(stream, this, msg));
	}

#endif

void MsgThread::SendIn(BasicInputMessage* msg, bool force)
	{
	if ( Terminating() && ! force )
		{
		delete msg;
		return;
		}

	DBG_LOG(DBG_THREADING, "Sending '%s' to %s ...", msg->Name().c_str(), Name().c_str());

	queue_in.Put(msg);
	++cnt_sent_in;
	}


void MsgThread::SendOut(BasicOutputMessage* msg, bool force)
	{
	if ( Terminating() && ! force )
		{
		delete msg;
		return;
		}

	queue_out.Put(msg);

	++cnt_sent_out;
	}

BasicOutputMessage* MsgThread::RetrieveOut()
	{
	BasicOutputMessage* msg = queue_out.Get();
	assert(msg);

	DBG_LOG(DBG_THREADING, "Retrieved '%s' from %s",  msg->Name().c_str(), Name().c_str());

	return msg;
	}

BasicInputMessage* MsgThread::RetrieveIn()
	{
	BasicInputMessage* msg = queue_in.Get();
	assert(msg);

#ifdef DEBUG
	string s = Fmt("Retrieved '%s' in %s",  msg->Name().c_str(), Name().c_str());
	Debug(DBG_THREADING, s.c_str());
#endif

	return msg;
	}

void MsgThread::Run()
	{
	while ( true )
		{
		// When requested to terminate, we only do so when
		// all input has been processed.
		if ( Terminating() && ! queue_in.Ready() )
			break;

		BasicInputMessage* msg = RetrieveIn();

		bool result = msg->Process();

		if ( ! result )
			{
			string s = msg->Name() + " failed, terminating thread";
			Error(s.c_str());
			Stop();
			break;
			}

		delete msg;
		}
	}

void MsgThread::GetStats(Stats* stats)
	{
	stats->sent_in = cnt_sent_in;
	stats->sent_out = cnt_sent_out;
	stats->pending_in = queue_in.Size();
	stats->pending_out = queue_out.Size();
	queue_in.GetStats(&stats->queue_in_stats);
	queue_out.GetStats(&stats->queue_out_stats);
	}

