#include <sys/socket.h>
#include <unistd.h>

#include "Manager.h"
#include "NetVar.h"
#include "iosource/Manager.h"

using namespace threading;

void HeartbeatTimer::Dispatch(double t, int is_expire)
	{
	if ( is_expire )
		return;

	thread_mgr->SendHeartbeats();
	thread_mgr->StartHeartbeatTimer();
	}

Manager::Manager()
	{
	DBG_LOG(DBG_THREADING, "Creating thread manager ...");

	did_process = true;
	next_beat = 0;
	}

Manager::~Manager()
	{
	if ( all_threads.size() )
		Terminate();

	if ( heartbeat_timer )
		delete heartbeat_timer;
	}

void Manager::Terminate()
	{
	DBG_LOG(DBG_THREADING, "Terminating thread manager ...");

	// First process remaining thread output for the message threads.
	do Flush(); while ( did_process );

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
	}

void Manager::AddThread(BasicThread* thread)
	{
	DBG_LOG(DBG_THREADING, "Adding thread %s ...", thread->Name());
	all_threads.push_back(thread);

	if ( ! heartbeat_timer )
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

		MsgThread* mt = dynamic_cast<MsgThread *>(t);

		if ( mt )
			msg_threads.remove(mt);

		t->Join();
		delete t;
		}
	}

void Manager::StartHeartbeatTimer()
	{
	heartbeat_timer = new HeartbeatTimer(network_time + BifConst::Threading::heartbeat_interval);
	timer_mgr->Add(heartbeat_timer);
	}

void Manager::Flush()
	{
	bool do_beat = false;

	if ( network_time && (network_time > next_beat || ! next_beat) )
		{
		do_beat = true;
		next_beat = ::network_time + BifConst::Threading::heartbeat_interval;
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
				if ( network_time )
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

		MsgThread* mt = dynamic_cast<MsgThread *>(t);

		if ( mt )
			msg_threads.remove(mt);

		t->Join();
		delete t;
		}

//	fprintf(stderr, "P %.6f %.6f do_beat=%d did_process=%d next_next=%.6f\n", network_time, timer_mgr->Time(), do_beat, (int)did_process, next_beat);
	}

const threading::Manager::msg_stats_list& threading::Manager::GetMsgThreadStats()
	{
	stats.clear();

	for ( msg_thread_list::iterator i = msg_threads.begin(); i != msg_threads.end(); i++ )
		{
		MsgThread* t = *i;

		MsgThread::Stats s;
		t->GetStats(&s);

		stats.push_back(std::make_pair(t->Name(),s));
		}

	return stats;
	}
