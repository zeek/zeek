
#ifndef THREADING_MANAGER_H
#define THREADING_MANAGER_H

#include <list>

#include "IOSource.h"

#include "BasicThread.h"
#include "MsgThread.h"

namespace threading {

class Manager : public IOSource
{
public:
	Manager();
	~Manager();

	void Terminate();

protected:
	friend class BasicThread;
	friend class MsgThread;

	void AddThread(BasicThread* thread);
	void AddMsgThread(MsgThread* thread);

	// IOSource interface.
	virtual void GetFds(int* read, int* write, int* except);
	virtual double NextTimestamp(double* network_time);
	virtual void Process();
	virtual const char* Tag()	{ return "threading::Manager"; }

private:
	static const int HEART_BEAT_INTERVAL = 1;

	typedef std::list<BasicThread*> all_thread_list;
	all_thread_list all_threads;

	typedef std::list<MsgThread*> msg_thread_list;
	msg_thread_list msg_threads;

	bool did_process;
	double next_beat;
};

}

extern threading::Manager* thread_mgr;

#endif
