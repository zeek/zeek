#ifndef THREADSAFEQUEUE_H
#define THREADSAFEQUEUE_H

#include <pthread.h>
#include <queue>
#include <deque>

namespace bro
{
	template <typename T>
	class QueueInterface
	{
	public:
		virtual T get() = 0;
		virtual void put(T) = 0;
		virtual bool ready() = 0;
		virtual ~QueueInterface() { }
	};
	
	/**
	 *  Just a simple threaded queue wrapper class.  Uses multiple queues and reads / writes in rotary fashion in an attempt to limit contention.
	 *  Due to locking granularity, bulk put / get is no faster than single put / get as long as FIFO guarantee is required.
	 */
	template <typename T>
	class ThreadSafeQueue : public QueueInterface<T>
	{
	public:
		ThreadSafeQueue()
		: NUM_QUEUES(DEFAULT_NUM_QUEUES), read_ptr(0), write_ptr(0)
			{ 
			hasdata = new pthread_cond_t[NUM_QUEUES];
			mutex = new pthread_mutex_t[NUM_QUEUES];
			messages = new std::queue<T>[NUM_QUEUES];
			for(int i = 0; i < NUM_QUEUES; ++i)
				{
				pthread_cond_init(&hasdata[i], NULL);
				pthread_mutex_init(&mutex[i], NULL);
				}
			}

		~ThreadSafeQueue()
			{
				delete[] hasdata;
				delete[] mutex;
				delete[] messages;
			}

		void put(T data)
			{
			pthread_mutex_lock(&mutex[write_ptr]);
			int old_write_ptr = write_ptr;
			bool should_signal = messages[write_ptr].empty();
			messages[write_ptr].push(data);
			if(should_signal)
				{
				pthread_cond_signal(&hasdata[write_ptr]);
				}
			write_ptr = (write_ptr + 1) % NUM_QUEUES;
			pthread_mutex_unlock(&mutex[old_write_ptr]);
			}

		T get()
			{
			pthread_mutex_lock(&mutex[read_ptr]);
			if(messages[read_ptr].empty())
				{
				pthread_cond_wait(&hasdata[read_ptr], &mutex[read_ptr]);
				}
			int old_read_ptr = read_ptr;
			T data = messages[read_ptr].front();
			messages[read_ptr].pop();
			read_ptr = (read_ptr + 1) % NUM_QUEUES;
			pthread_mutex_unlock(&mutex[old_read_ptr]);
			return data;
			}

		bool ready()
			{
			pthread_mutex_lock(&mutex[read_ptr]);
			const bool ret = !messages[read_ptr].empty();
			pthread_mutex_unlock(&mutex[read_ptr]);
			return ret;
			}

	protected:
		const static int 	DEFAULT_NUM_QUEUES = 8;     // Default number of queues
		const int			NUM_QUEUES;                 // Number of queues to use for this structure; locking proceeds in rotary fashion
		pthread_cond_t 		*hasdata;               	// Signals when data becomes available
		pthread_mutex_t 	*mutex;                 	// This is locked when modifying the mutex
		std::queue<T>  		*messages;                  // Actually holds the queued messages
		unsigned char   	read_ptr;                   // Where the next operation will read from
		unsigned char   	write_ptr;                  // Where the next operation will write to
	};

}

#endif

