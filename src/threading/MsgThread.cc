#include "zeek/threading/MsgThread.h"

#include <unistd.h>
#include <signal.h>
#include <fcntl.h>

#include "zeek/DebugLogger.h"
#include "zeek/threading/Manager.h"
#include "zeek/iosource/Manager.h"
#include "zeek/RunState.h"

// Set by Zeek's main signal handler.
extern int signal_val;

namespace zeek::threading {
namespace detail {

////// Messages.

// Signals child thread to shutdown operation.
class FinishMessage final : public InputMessage<MsgThread>
{
public:
	FinishMessage(MsgThread* thread, double network_time) : InputMessage<MsgThread>("Finish", thread),
		network_time(network_time) { }

	bool Process() override	{
		if ( Object()->child_finished )
			return true;
		bool result = Object()->OnFinish(network_time);
		Object()->Finished();
		return result;
	}

private:
	double network_time;
};

// Signals main thread that operations shut down.
class FinishedMessage final : public OutputMessage<MsgThread>
{
public:
	FinishedMessage(MsgThread* thread)
		: OutputMessage<MsgThread>("FinishedMessage", thread)
		{ }

	bool Process() override {
		Object()->main_finished = true;
		return true;
	}
};

/// Sends a heartbeat to the child thread.
class HeartbeatMessage final : public InputMessage<MsgThread>
{
public:
	HeartbeatMessage(MsgThread* thread, double arg_network_time, double arg_current_time)
		: InputMessage<MsgThread>("Heartbeat", thread)
		{ network_time = arg_network_time; current_time = arg_current_time; }

	bool Process() override	{
		return Object()->OnHeartbeat(network_time, current_time);
	}

private:
	double network_time;
	double current_time;
};

// A message from the child to be passed on to the Reporter.
class ReporterMessage final : public OutputMessage<MsgThread>
{
public:
	enum Type {
		INFO, WARNING, ERROR, FATAL_ERROR, FATAL_ERROR_WITH_CORE,
		INTERNAL_WARNING, INTERNAL_ERROR
	};

	ReporterMessage(Type arg_type, MsgThread* thread, const char* arg_msg)
		: OutputMessage<MsgThread>("ReporterMessage", thread)
		{ type = arg_type; msg = util::copy_string(arg_msg); }

	~ReporterMessage() override 	 { delete [] msg; }

	bool Process() override;

private:
	const char* msg;
	Type type;
};

// A message from the the child to the main process, requesting suicide.
class KillMeMessage final : public OutputMessage<MsgThread>
{
public:
	KillMeMessage(MsgThread* thread)
		: OutputMessage<MsgThread>("ReporterMessage", thread) 	{}

	bool Process() override
		{
		Object()->SignalStop();
		Object()->WaitForStop();
		thread_mgr->KillThread(Object());
		return true;
		}
};

#ifdef DEBUG
// A debug message from the child to be passed on to the DebugLogger.
class DebugMessage final : public OutputMessage<MsgThread>
{
public:
	DebugMessage(DebugStream arg_stream, MsgThread* thread, const char* arg_msg)
		: OutputMessage<MsgThread>("DebugMessage", thread)
		{ stream = arg_stream; msg = util::copy_string(arg_msg); }

	~DebugMessage() override	{ delete [] msg; }

	bool Process() override
		{
		zeek::detail::debug_logger.Log(stream, "%s: %s", Object()->Name(), msg);
		return true;
		}
private:
	const char* msg;
	DebugStream stream;
};
#endif

// An event that the child wants to pass into the main event queue
class SendEventMessage final : public OutputMessage<MsgThread> {
public:
	SendEventMessage(MsgThread* thread, const char* name, const int num_vals, Value* *val)
		: OutputMessage<MsgThread>("SendEvent", thread),
	  name(util::copy_string(name)), num_vals(num_vals), val(val) {}

	~SendEventMessage() override	{ delete [] name; }

	bool Process() override
		{
		bool success = thread_mgr->SendEvent(Object(), name, num_vals, val);

		if ( ! success )
			reporter->Error("SendEvent for event %s failed", name);

		return true; // We do not want to die if sendEvent fails because the event did not return.
		}

private:
	const char* name;
	const int num_vals;
	Value* *val;
};

bool ReporterMessage::Process()
	{
	switch ( type ) {

	case INFO:
		reporter->Info("%s: %s", Object()->Name(), msg);
		break;

	case WARNING:
		reporter->Warning("%s: %s", Object()->Name(), msg);
		break;

	case ERROR:
		reporter->Error("%s: %s", Object()->Name(), msg);
		break;

	case FATAL_ERROR:
		reporter->FatalError("%s: %s", Object()->Name(), msg);
		break;

	case FATAL_ERROR_WITH_CORE:
		reporter->FatalErrorWithCore("%s: %s", Object()->Name(), msg);
		break;

	case INTERNAL_WARNING:
		reporter->InternalWarning("%s: %s", Object()->Name(), msg);
		break;

	case INTERNAL_ERROR :
		reporter->InternalError("%s: %s", Object()->Name(), msg);
		break;

	default:
		reporter->InternalError("unknown ReporterMessage type %d", type);
	}

	return true;
	}

} // namespace detail

////// Methods.

Message::~Message()
	{
	delete [] name;
	}

MsgThread::MsgThread() : BasicThread(), queue_in(this, nullptr), queue_out(nullptr, this)
	{
	cnt_sent_in.store(0);
	cnt_sent_out.store(0);

	main_finished = false;
	child_finished = false;
	child_sent_finish = false;
	failed = false;
	thread_mgr->AddMsgThread(this);

	if ( ! iosource_mgr->RegisterFd(flare.FD(), this) )
		reporter->FatalError("Failed to register MsgThread fd with iosource_mgr");

	SetClosed(false);
	}

MsgThread::~MsgThread()
	{
	// Unregister this thread from the iosource manager so it doesn't wake
	// up the main poll anymore.
	iosource_mgr->UnregisterFd(flare.FD(), this);
	}

void MsgThread::OnSignalStop()
	{
	if ( main_finished || Killed() || child_sent_finish )
		return;

	child_sent_finish = true;
	// Signal thread to terminate.
	SendIn(new detail::FinishMessage(this, run_state::network_time), true);
	}

void MsgThread::OnWaitForStop()
	{
	int signal_count = 0;
	int old_signal_val = signal_val;
	signal_val = 0;

	int cnt = 0;
	uint64_t last_size = 0;
	uint64_t cur_size = 0;

	while ( ! main_finished )
		{
		// Terminate if we get another kill signal.
		if ( signal_val == SIGTERM || signal_val == SIGINT )
			{
			++signal_count;

			if ( signal_count == 1 )
				{
				// Abort all threads here so that we won't hang next
				// on another one.
				fprintf(stderr, "received signal while waiting for thread %s, aborting all ...\n", Name());
				thread_mgr->KillThreads();
				}
			else
				{
				// More than one signal. Abort processing
				// right away. on another one.
				fprintf(stderr, "received another signal while waiting for thread %s, aborting processing\n", Name());
				exit(1);
				}

			signal_val = 0;
			}

		if ( ! Killed() )
			queue_in.WakeUp();

		while ( HasOut() )
			{
			Message* msg = RetrieveOut();
			assert ( msg );

			if ( ! msg->Process() )
				reporter->Error("%s failed during thread termination", msg->Name());

			delete msg;
			}

		if ( ! Killed() )
			usleep(1000);
		}

	signal_val = old_signal_val;
	}

void MsgThread::OnKill()
	{
	SetClosed(true);

	// Send a message to unblock the reader if its currently waiting for
	// input. This is just an optimization to make it terminate more
	// quickly, even without the message it will eventually time out.
	queue_in.WakeUp();
	}

void MsgThread::Heartbeat()
	{
	if ( child_sent_finish )
		return;

	SendIn(new detail::HeartbeatMessage(this, run_state::network_time, util::current_time()));
	}

void MsgThread::Finished()
	{
	child_finished = true;
	SendOut(new detail::FinishedMessage(this));
	}

void MsgThread::Info(const char* msg)
	{
	SendOut(new detail::ReporterMessage(detail::ReporterMessage::INFO, this, msg));
	}

void MsgThread::Warning(const char* msg)
	{
	SendOut(new detail::ReporterMessage(detail::ReporterMessage::WARNING, this, msg));
	}

void MsgThread::Error(const char* msg)
	{
	SendOut(new detail::ReporterMessage(detail::ReporterMessage::ERROR, this, msg));
	}

void MsgThread::FatalError(const char* msg)
	{
	SendOut(new detail::ReporterMessage(detail::ReporterMessage::FATAL_ERROR, this, msg));
	}

void MsgThread::FatalErrorWithCore(const char* msg)
	{
	SendOut(new detail::ReporterMessage(detail::ReporterMessage::FATAL_ERROR_WITH_CORE, this, msg));
	}

void MsgThread::InternalWarning(const char* msg)
	{
	SendOut(new detail::ReporterMessage(detail::ReporterMessage::INTERNAL_WARNING, this, msg));
	}

void MsgThread::InternalError(const char* msg)
	{
	// This one aborts immediately.
	fprintf(stderr, "internal error in thread: %s\n", msg);
	abort();
	}

#ifdef DEBUG

void MsgThread::Debug(DebugStream stream, const char* msg)
	{
	SendOut(new detail::DebugMessage(stream, this, msg));
	}

#endif

void MsgThread::SendIn(BasicInputMessage* msg, bool force)
	{
	if ( Terminating() && ! force )
		{
		delete msg;
		return;
		}

	DBG_LOG(DBG_THREADING, "Sending '%s' to %s ...", msg->Name(), Name());

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

	flare.Fire();
	}

void MsgThread::SendEvent(const char* name, const int num_vals, Value* *vals)
	{
	SendOut(new detail::SendEventMessage(this, name, num_vals, vals));
	}

BasicOutputMessage* MsgThread::RetrieveOut()
	{
	BasicOutputMessage* msg = queue_out.Get();
	if ( ! msg )
		return nullptr;

	DBG_LOG(DBG_THREADING, "Retrieved '%s' from %s",  msg->Name(), Name());

	return msg;
	}

BasicInputMessage* MsgThread::RetrieveIn()
	{
	BasicInputMessage* msg = queue_in.Get();

	if ( ! msg )
		return nullptr;

#ifdef DEBUG
	std::string s = Fmt("Retrieved '%s' in %s",  msg->Name(), Name());
	Debug(DBG_THREADING, s.c_str());
#endif

	return msg;
	}

void MsgThread::Run()
	{
	while ( ! (child_finished || Killed() ) )
		{
		BasicInputMessage* msg = RetrieveIn();

		if ( ! msg )
			continue;

		bool result = msg->Process();

		delete msg;

		if ( ! result )
			{
			Error("terminating thread");

			// This will eventually kill this thread, but only
			// after all other outgoing messages (in particular
			// error messages have been processed by then main
			// thread).
			SendOut(new detail::KillMeMessage(this));
			failed = true;
			}
		}

	// In case we haven't sent the finish method yet, do it now. Reading
	// global network_time here should be fine, it isn't changing
	// anymore.
	if ( ! child_finished && ! Killed() )
		{
		OnFinish(run_state::network_time);
		Finished();
		}
	}

void MsgThread::GetStats(Stats* stats)
	{
	stats->sent_in = cnt_sent_in.load();
	stats->sent_out = cnt_sent_out.load();
	stats->pending_in = queue_in.Size();
	stats->pending_out = queue_out.Size();
	queue_in.GetStats(&stats->queue_in_stats);
	queue_out.GetStats(&stats->queue_out_stats);
	}

void MsgThread::Process()
	{
	flare.Extinguish();

	while ( HasOut() )
		{
		Message* msg = RetrieveOut();
		assert(msg);

		if ( ! msg->Process() )
			{
			reporter->Error("%s failed, terminating thread", msg->Name());
			SignalStop();
			}

		delete msg;
		}
	}

} // namespace zeek::threading
