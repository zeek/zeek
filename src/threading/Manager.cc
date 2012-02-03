
#include "Manager.h"

using namespace threading;

Manager::Manager()
	{
	DBG_LOG(DBG_THREADING, "Creating thread manager ...");

	did_process = false;
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
	do Process(); while ( did_process );

	// Signal all to stop.
	for ( all_thread_list::iterator i = all_threads.begin(); i != all_threads.end(); i++ )
		(*i)->Stop();

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

void Manager::KillThreads()
	{
	DBG_LOG(DBG_THREADING, "Killing threads ...");

	for ( all_thread_list::iterator i = all_threads.begin(); i != all_threads.end(); i++ )
		(*i)->Kill();
	}

void Manager::AddThread(BasicThread* thread)
	{
	DBG_LOG(DBG_THREADING, "Adding thread %s ...", thread->Name().c_str());
	all_threads.push_back(thread);
	}

void Manager::AddMsgThread(MsgThread* thread)
	{
	DBG_LOG(DBG_THREADING, "%s is a MsgThread ...", thread->Name().c_str());
	msg_threads.push_back(thread);
	}

void Manager::GetFds(int* read, int* write, int* except)
	{
	}

double Manager::NextTimestamp(double* network_time)
	{
	if ( did_process || ! next_beat == 0 )
		// If we had something to process last time (or haven't had a
		// chance to check yet), we want to check for more asap.
		return timer_mgr->Time();

	// Else we assume we don't have much to do at all and wait for the next heart beat.
	return next_beat;
	}

void Manager::Process()
	{
	bool do_beat = (next_beat == 0 || network_time >= next_beat);

	did_process = false;

	for ( msg_thread_list::iterator i = msg_threads.begin(); i != msg_threads.end(); i++ )
		{
		MsgThread* t = *i;

		if ( do_beat )
			t->Heartbeat();

		if ( ! t->HasOut() )
			continue;

		Message* msg = t->RetrieveOut();

		if ( msg->Process() )
			did_process = true;

		else
			{
			string s = msg->Name() + " failed, terminating thread";
			reporter->Error("%s", s.c_str());
			t->Stop();
			}

		delete msg;
		}

	if ( do_beat )
		next_beat = network_time + HEART_BEAT_INTERVAL;
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


