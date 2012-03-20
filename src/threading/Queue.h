
#ifndef THREADING_QUEUE_H
#define THREADING_QUEUE_H

#include <pthread.h>
#include <queue>
#include <deque>
#include <stdint.h>

#include "Reporter.h"

#undef Queue // Defined elsewhere unfortunately.

namespace threading {

/**
 * A thread-safe single-reader single-writer queue.
 *
 * The implementation uses multiple queues and reads/writes in rotary fashion
 * in an attempt to limit contention.
 *
 * All Queue instances must be instantiated by Bro's main thread.
 *
 * TODO: Unclear how critical performance is for this qeueue. We could like;y
 * optimize it further if helpful.
 */
template<typename T>
class Queue
{
public:
	/**
	 * Constructor.
	 */
	Queue();

	/**
	 * Destructor.
	 */
	~Queue();

	/**
	 * Retrieves one elment.
	 */
	T Get();

	/**
	* Queues one element.
	* 
	* @param reliable true if the message *MUST* be delivered (ignore max queue size).
	* @return true if the message was inserted successfully, and false if the message was dropped.
	*/
	bool Put(T data, const bool reliable);

	/**
	 * Unreliably queues one element.
	 *
	 * @return true if the message was inserted successfully, and false if the message was dropped.
	 */
	bool Put(T data);

	/**
	 * Returns true if the next Get() operation will succeed.
	 */
	bool Ready();

	/**
	 * Returns the number of queued items not yet retrieved.
	 */
	uint64_t Size();

private:
	static const int NUM_QUEUES = 8;
	static const int QUEUE_HIGH_WM = 100000;

	pthread_mutex_t mutex[NUM_QUEUES];	// Mutex protected shared accesses.
	pthread_cond_t has_data[NUM_QUEUES];	// Signals when data becomes available
	std::queue<T> messages[NUM_QUEUES];	// Actually holds the queued messages

	int read_ptr;	// Where the next operation will read from
	int write_ptr;	// Where the next operation will write to
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
inline Queue<T>::Queue()
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
inline Queue<T>::~Queue()
	{
	for( int i = 0; i < NUM_QUEUES; ++i )
		{
		pthread_cond_destroy(&has_data[i]);
		pthread_mutex_destroy(&mutex[i]);
		}
	}

template<typename T>
inline T Queue<T>::Get()
	{
	safe_lock(&mutex[read_ptr]);

	int old_read_ptr = read_ptr;

	if ( messages[read_ptr].empty() )
		pthread_cond_wait(&has_data[read_ptr], &mutex[read_ptr]);

	T data = messages[read_ptr].front();
	messages[read_ptr].pop();

	read_ptr = (read_ptr + 1) % NUM_QUEUES;

	safe_unlock(&mutex[old_read_ptr]);

	return data;
	}

template<typename T>
inline bool Queue<T>::Put(T data, const bool reliable)
	{
	safe_lock(&mutex[write_ptr]);

	if(!reliable && (messages[write_ptr].size() * NUM_QUEUES > QUEUE_HIGH_WM))
		{
		safe_unlock(&mutex[write_ptr]);
		return false;
		}

	int old_write_ptr = write_ptr;

	bool need_signal = messages[write_ptr].empty();

	messages[write_ptr].push(data);

	if ( need_signal )
		pthread_cond_signal(&has_data[write_ptr]);

	write_ptr = (write_ptr + 1) % NUM_QUEUES;

	safe_unlock(&mutex[old_write_ptr]);
	return true;
	}

template<typename T>
inline bool Queue<T>::Put(T data)
	{
	Put(data, false);
	}


template<typename T>
inline bool Queue<T>::Ready()
	{
	safe_lock(&mutex[read_ptr]);

	bool ret = (messages[read_ptr].size());

	safe_unlock(&mutex[read_ptr]);

	return ret;
	}

template<typename T>
inline uint64_t Queue<T>::Size()
	{
	// Need to lock all queues.
	for ( int i = 0; i < NUM_QUEUES; i++ )
		safe_lock(&mutex[i]);

	uint64_t size = 0;

	for ( int i = 0; i < NUM_QUEUES; i++ )
		size += messages[i].size();

	for ( int i = 0; i < NUM_QUEUES; i++ )
		safe_unlock(&mutex[i]);

	return size;
	}

}

#endif

