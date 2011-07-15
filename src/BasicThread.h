#ifndef BASICTHREAD_H
#define BASICTHREAD_H

#include "ThreadSafeQueue.h"
#include <typeinfo>

namespace bro
{

	class ThreadInterface
	{
	public:
	ThreadInterface()
	: thread_finished(false) { }

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
		pthread_join(thread, NULL);
		}

	virtual void run() = 0;
	protected:
		pthread_t thread;
		bool thread_finished;
	};

	class MessageEvent
	{
	public:
		virtual bool process() = 0;
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
			while(!thread_finished)
				{
				MessageEvent *msg = in_queue.get();
				bool res = msg->process();
				if(!res)
					{
					putNotification(new ErrorReport(msg, "process() failed"));
					thread_finished = true;
					}
				delete msg;
				}
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
}

#endif
