#include "zeek/threading/Manager.h"

#include <sys/socket.h>
#include <unistd.h>

#include "zeek/Event.h"
#include "zeek/IPAddr.h"
#include "zeek/NetVar.h"
#include "zeek/RunState.h"
#include "zeek/iosource/Manager.h"

namespace zeek::threading
	{
namespace detail
	{

void HeartbeatTimer::Dispatch(double t, bool is_expire)
	{
	if ( is_expire )
		return;

	thread_mgr->SendHeartbeats();
	thread_mgr->StartHeartbeatTimer();
	}

	} // namespace detail

Manager::Manager()
	{
	DBG_LOG(DBG_THREADING, "Creating thread manager ...");

	did_process = true;
	next_beat = 0;
	terminating = false;
	}

Manager::~Manager()
	{
	if ( all_threads.size() )
		Terminate();
	}

void Manager::Terminate()
	{
	DBG_LOG(DBG_THREADING, "Terminating thread manager ...");
	terminating = true;

	// First process remaining thread output for the message threads.
	do
		Flush();
		while ( did_process );

		// Signal all to stop.

		for ( all_thread_list::iterator i = all_threads.begin(); i != all_threads.end(); i++ )
			(*i)->SignalStop();

		for ( all_thread_list::iterator i = all_threads.begin(); i != all_threads.end(); i++ )
			(*i)->WaitForStop();

		// Then join them all.
		for ( all_thread_list::iterator i = all_threads.begin(); i != all_threads.end(); i++ )
			{
			(*i)->Join();
			delete *i;
			}

		all_threads.clear();
		msg_threads.clear();
		terminating = false;
	}

void Manager::AddThread(BasicThread* thread)
	{
	DBG_LOG(DBG_THREADING, "Adding thread %s ...", thread->Name());
	all_threads.push_back(thread);

	if ( ! heartbeat_timer_running )
		StartHeartbeatTimer();
	}

void Manager::AddMsgThread(MsgThread* thread)
	{
	DBG_LOG(DBG_THREADING, "%s is a MsgThread ...", thread->Name());
	msg_threads.push_back(thread);
	}

void Manager::KillThreads()
	{
	DBG_LOG(DBG_THREADING, "Killing threads ...");

	for ( all_thread_list::iterator i = all_threads.begin(); i != all_threads.end(); i++ )
		(*i)->Kill();
	}

void Manager::KillThread(BasicThread* thread)
	{
	DBG_LOG(DBG_THREADING, "Killing thread %s ...", thread->Name());
	thread->Kill();
	}

void Manager::SendHeartbeats()
	{
	for ( MsgThread* thread : msg_threads )
		thread->Heartbeat();

	// Since this is a regular timer, this is also an ideal place to check whether we have
	// and dead threads and to delete them.
	all_thread_list to_delete;
	for ( all_thread_list::iterator i = all_threads.begin(); i != all_threads.end(); i++ )
		{
		BasicThread* t = *i;

		if ( t->Killed() )
			to_delete.push_back(t);
		}

	for ( all_thread_list::iterator i = to_delete.begin(); i != to_delete.end(); i++ )
		{
		BasicThread* t = *i;
		t->WaitForStop();

		all_threads.remove(t);

		MsgThread* mt = dynamic_cast<MsgThread*>(t);

		if ( mt )
			msg_threads.remove(mt);

		t->Join();
		delete t;
		}
	}

void Manager::StartHeartbeatTimer()
	{
	heartbeat_timer_running = true;
	zeek::detail::timer_mgr->Add(new detail::HeartbeatTimer(
		run_state::network_time + BifConst::Threading::heartbeat_interval));
	}

// Raise everything in here as warnings so it is passed to scriptland without
// looking "fatal". In addition to these warnings, ReaderBackend will queue
// one reporter message.
bool Manager::SendEvent(MsgThread* thread, const std::string& name, const int num_vals,
                        Value** vals) const
	{
	EventHandler* handler = event_registry->Lookup(name);
	if ( handler == nullptr )
		{
		reporter->Warning("Thread %s: Event %s not found", thread->Name(), name.c_str());
		Value::delete_value_ptr_array(vals, num_vals);
		return false;
		}

#ifdef DEBUG
	DBG_LOG(DBG_INPUT, "Thread %s: SendEvent for event %s with %d vals", thread->Name(),
	        name.c_str(), num_vals);
#endif

	const auto& type = handler->GetType()->Params();
	int num_event_vals = type->NumFields();
	if ( num_vals != num_event_vals )
		{
		reporter->Warning("Thread %s: Wrong number of values for event %s", thread->Name(),
		                  name.c_str());
		Value::delete_value_ptr_array(vals, num_vals);
		return false;
		}

	bool convert_error = false;

	Args vl;
	vl.reserve(num_vals);

	for ( int j = 0; j < num_vals; j++ )
		{
		Val* v = Value::ValueToVal(std::string("thread ") + thread->Name(), vals[j], convert_error);
		vl.emplace_back(AdoptRef{}, v);

		if ( v && ! convert_error && ! same_type(type->GetFieldType(j), v->GetType()) )
			{
			convert_error = true;
			type->GetFieldType(j)->Error("SendEvent types do not match", v->GetType().get());
			}
		}

	Value::delete_value_ptr_array(vals, num_vals);

	if ( convert_error )
		return false;
	else if ( handler )
		event_mgr.Enqueue(handler, std::move(vl), util::detail::SOURCE_LOCAL);

	return true;
	}

void Manager::Flush()
	{
	bool do_beat = false;

	if ( run_state::network_time && (run_state::network_time > next_beat || ! next_beat) )
		{
		do_beat = true;
		next_beat = run_state::network_time + BifConst::Threading::heartbeat_interval;
		}

	did_process = false;

	for ( msg_thread_list::iterator i = msg_threads.begin(); i != msg_threads.end(); i++ )
		{
		MsgThread* t = *i;

		if ( do_beat )
			t->Heartbeat();

		while ( t->HasOut() )
			{
			Message* msg = t->RetrieveOut();
			assert(msg);

			if ( msg->Process() )
				{
				if ( run_state::network_time )
					did_process = true;
				}

			else
				{
				reporter->Error("%s failed, terminating thread", msg->Name());
				t->SignalStop();
				}

			delete msg;
			}
		}

	all_thread_list to_delete;

	for ( all_thread_list::iterator i = all_threads.begin(); i != all_threads.end(); i++ )
		{
		BasicThread* t = *i;

		if ( t->Killed() )
			to_delete.push_back(t);
		}

	for ( all_thread_list::iterator i = to_delete.begin(); i != to_delete.end(); i++ )
		{
		BasicThread* t = *i;
		t->WaitForStop();

		all_threads.remove(t);

		MsgThread* mt = dynamic_cast<MsgThread*>(t);

		if ( mt )
			msg_threads.remove(mt);

		t->Join();
		delete t;
		}

	// fprintf(stderr, "P %.6f %.6f do_beat=%d did_process=%d next_next=%.6f\n",
	// run_state::network_time,
	//         detail::timer_mgr->Time(), do_beat, (int)did_process, next_beat);
	}

const threading::Manager::msg_stats_list& threading::Manager::GetMsgThreadStats()
	{
	stats.clear();

	for ( msg_thread_list::iterator i = msg_threads.begin(); i != msg_threads.end(); i++ )
		{
		MsgThread* t = *i;

		MsgThread::Stats s;
		t->GetStats(&s);

		stats.push_back(std::make_pair(t->Name(), s));
		}

	return stats;
	}

	} // namespace zeek::threading
