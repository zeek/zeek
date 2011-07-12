#ifndef BASICTHREAD_H
#define BASICTHREAD_H

#include "ThreadSafeQueue.h"

namespace bro
{
	class ThreadNotification
	{
	public:
		enum MessageType
		{
			NOTIFY_UNKNOWN,
			NOTIFY_ERROR,
			NOTIFY_FATAL,
			NOTIFY_FORCE_SHUTDOWN_ACK,
			NOTIFY_TERMINATED_ACK
		};

		ThreadNotification(const MessageType c)
		: code(c) { }

		MessageType getCode() const {return code; }
	private:
		const MessageType code;
	};

	// TODO: Get rid of RefType ...
	template <typename InQueueType, typename RefType>
	class BasicThread
	{
	public:
		BasicThread()
		: thread_finished(false) { }

		static void *launcher(void *args)
			{
			((BasicThread *)(args))->run();
			return 0;
			}

		virtual void run()
			{
			while(!thread_finished)
				{
				InQueueType msg = in_queue.get();
				bool res = msg->execute((RefType)this);
				delete msg;
				if(!res)
					{
					putNotification(ThreadNotification(ThreadNotification::NOTIFY_FATAL));
					return;
					}
				}
			}

		void start()
			{
			pthread_create(&thread, NULL, BasicThread::launcher, this);
			}

		void putNotification(ThreadNotification n)
			{
			out_queue.put(n);
			}

		ThreadNotification getNotification()
			{
			return out_queue.get();
			}
		
		bool hasNotification()
			{
			return out_queue.ready();
			}

		void putMessage(InQueueType type)
			{
			in_queue.put(type);
			}

		InQueueType getMessage()
			{
			return in_queue.get();
			}

	protected:
		bool thread_finished;
	private:
		ThreadSafeQueue<InQueueType> in_queue;
		ThreadSafeQueue<ThreadNotification> out_queue;
		pthread_t thread;
	};
}

#endif
