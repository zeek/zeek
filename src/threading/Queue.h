
#ifndef THREADING_QUEUE_H
#define THREADING_QUEUE_H

#include <pthread.h>
#include <queue>
#include <deque>
#include <stdint.h>

#include "Reporter.h"

namespace threading {

/**
 *  Just a simple threaded queue wrapper class.  Uses multiple queues and reads / writes in rotary fashion in an attempt to limit contention.
 *  Due to locking granularity, bulk put / get is no faster than single put / get as long as FIFO guarantee is required.
 */

template<typename T>
class Queue_
{
public:
	Queue_();
	~Queue_();

	T Get();
	void Put(T data);
	bool Ready();
	uint64_t Size();

private:
	static const int NUM_QUEUES = 8;

	pthread_mutex_t mutex[NUM_QUEUES];	// Mutex protected shared accesses.
	pthread_cond_t has_data[NUM_QUEUES];	// Signals when data becomes available
	std::queue<T> messages[NUM_QUEUES];	// Actually holds the queued messages

	int read_ptr;	// Where the next operation will read from
	int write_ptr;	// Where the next operation will write to
	uint64_t size;
};

inline static void safe_lock(pthread_mutex_t* mutex)
	{
	if ( pthread_mutex_lock(mutex) != 0 )
		reporter->FatalErrorWithCore("cannot lock mutex");
	}

inline static void safe_unlock(pthread_mutex_t* mutex)
	{
	if ( pthread_mutex_unlock(mutex) != 0 )
		reporter->FatalErrorWithCore("cannot unlock mutex");
	}

template<typename T>
inline Queue_<T>::Queue_()
	{
	read_ptr = 0;
	write_ptr = 0;

	for( int i = 0; i < NUM_QUEUES; ++i )
		{
		if ( pthread_cond_init(&has_data[i], NULL) != 0 )
			reporter->FatalError("cannot init queue condition variable");

		if ( pthread_mutex_init(&mutex[i], NULL) != 0 )
			reporter->FatalError("cannot init queue mutex");
		}
	}

template<typename T>
inline Queue_<T>::~Queue_()
	{
	for( int i = 0; i < NUM_QUEUES; ++i )
		{
		pthread_cond_destroy(&has_data[i]);
		pthread_mutex_destroy(&mutex[i]);
		}
	}

template<typename T>
inline T Queue_<T>::Get()
	{
	safe_lock(&mutex[read_ptr]);

	int old_read_ptr = read_ptr;

	if ( messages[read_ptr].empty() )
		pthread_cond_wait(&has_data[read_ptr], &mutex[read_ptr]);

	T data = messages[read_ptr].front();
	messages[read_ptr].pop();
	--size;

	read_ptr = (read_ptr + 1) % NUM_QUEUES;

	safe_unlock(&mutex[old_read_ptr]);

	return data;
	}

template<typename T>
inline void Queue_<T>::Put(T data)
	{
	safe_lock(&mutex[write_ptr]);

	int old_write_ptr = write_ptr;

	bool need_signal = messages[write_ptr].empty();

	messages[write_ptr].push(data);
	++size;

	if ( need_signal )
		pthread_cond_signal(&has_data[write_ptr]);

	write_ptr = (write_ptr + 1) % NUM_QUEUES;

	safe_unlock(&mutex[old_write_ptr]);
	}


template<typename T>
inline bool Queue_<T>::Ready()
	{
	safe_lock(&mutex[read_ptr]);

	bool ret = (messages[read_ptr].size());

	safe_unlock(&mutex[read_ptr]);

	return ret;
	}

template<typename T>
inline uint64_t Queue_<T>::Size()
	{
	safe_lock(&mutex[read_ptr]);

	uint64_t s = size;

	safe_unlock(&mutex[read_ptr]);

	return s;
	}

}

#endif

