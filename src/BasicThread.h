#ifndef BASICTHREAD_H
#define BASICTHREAD_H

#include "ThreadSafeQueue.h"
#include <typeinfo>
#include <sys/signal.h>
#include <signal.h>
#include <pthread.h>

class ThreadInterface
{
public:
ThreadInterface()
: thread_finished(false), evt_count(0) { }

static void *launcher(void *args)
	{
	((ThreadInterface *)(args))->run();
	return 0;
	}

void start()
	{
	pthread_create(&thread, NULL, ThreadInterface::launcher, this);
	}

void stop()
	{
	thread_finished = true;
	}

void join()
	{
	// printf("**** Joining on thread:%x\n", (unsigned int)thread);
	assert(!pthread_join(thread, NULL));
	// printf("**** JOIN COMPLETE\n");
	}

virtual void run() = 0;
protected:
	pthread_t thread;
	bool thread_finished;
	size_t evt_count;
};

class MessageEvent
{
public:
	MessageEvent() { /*printf("ctor: %p -- %x\n", this, (unsigned int)(pthread_self()));*/ }
	virtual bool process() = 0;
	virtual ~MessageEvent() { /*printf("dtor: %p -- %x\n", this, (unsigned int)(pthread_self()));*/ }
};

class ErrorReport : public MessageEvent
{
public:
	ErrorReport(const MessageEvent *src, const std::string message)
	: src(src), message(message) { }

	ErrorReport(const std::string message)
	: src(this), message(message) { }

	bool process()
		{
		fprintf(stderr, "%s: %s", typeid(*src).name(), message.c_str());
		return true;
		}

private:
	const MessageEvent *src;
	const std::string message;
};

class TerminateThread : public MessageEvent
{
public:
	TerminateThread(ThreadInterface &ref)
	: ref(ref) { }
	
	bool process()
		{
		ref.stop();
		return true;
		}

private:
	ThreadInterface &ref;
};

class BasicThread : public ThreadInterface
{
public:
	BasicThread(QueueInterface<MessageEvent *>& in_q, QueueInterface<MessageEvent *>& out_q)
	: in_queue(in_q), out_queue(out_q) { }

	void run()
		{
		sigset_t mask_set;
		sigfillset(&mask_set);
		int res = pthread_sigmask(SIG_BLOCK, &mask_set, NULL);
		assert(res == 0);  // 
		// unsigned int id = (unsigned int)(pthread_self());
		while(!thread_finished)
			{
			MessageEvent *msg = in_queue.get();
			// printf("%x:%u (%s) -- %p\n", id, (unsigned int)evt_count, typeid(*msg).name(), msg);
			bool res = msg->process();
			++evt_count;
			if(!res)
				{
				putNotification(new ErrorReport(msg, "process() failed"));
				thread_finished = true;
				}
			delete msg;
			}
		if(in_queue.ready())
			{
			printf("Warning: Unprocessed events in queue at thread shutdown.\n");
			}
		// printf("Thread shutting down after processing %lu events.\n", evt_count);
		}

	MessageEvent *getNotification()
		{
		return out_queue.get();
		}
	
	bool hasNotification()
		{
		return out_queue.ready();
		}

	void putMessage(MessageEvent * const type)
		{
		in_queue.put(type);
		}
	
	BasicThread& operator=(const BasicThread &thr)
		{
		if(this == &thr)
			return *this;
		in_queue = thr.in_queue;
		out_queue = thr.out_queue;
		return *this;
		}
protected:
	// Thread-local access to these functions.
	void putNotification(MessageEvent *notification)
		{
		out_queue.put(notification);
		}

	MessageEvent *getMessage()
		{
		return in_queue.get();
		}

private:
	QueueInterface<MessageEvent *>& in_queue;
	QueueInterface<MessageEvent *>& out_queue;
};

#endif
