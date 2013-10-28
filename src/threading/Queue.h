#ifndef THREADING_QUEUE_H
#define THREADING_QUEUE_H

#include <pthread.h>
#include <queue>
#include <deque>
#include <stdint.h>
#include <sys/time.h>

#include "Reporter.h"
#include "BasicThread.h"

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
	 *
	 * reader, writer: The corresponding threads. This is for checking
	 * whether they have terminated so that we can abort I/O opeations.
	 * Can be left null for the main thread.
	 */
	Queue(BasicThread* arg_reader, BasicThread* arg_writer);

	/**
	 * Destructor.
	 */
	~Queue();

	/**
	 * Retrieves one element. This may block for a little while of no
	 * input is available and eventually return with a null element if
	 * nothing shows up.
	 */
	T Get();

	/**
	 * Queues one element.
	 */
	void Put(T data);

	/**
	 * Returns true if the next Get() operation will succeed.
	 */
	bool Ready();

	/**
	 * Returns true if the next Get() operation might succeed. This
	 * function may occasionally return a value not indicating the actual
	 * state, but won't do so very often. Note that this means that it can
	 * consistently return false even if there is something in the Queue.
	 * You have to check real queue status from time to time to be sure that
	 * it is empty. In other words, this method helps to avoid locking the queue
	 * frequently, but doesn't allow you to forgo it completely.
	 */
	bool MaybeReady() { return (num_reads != num_writes); }

	/** Wake up the reader if it's currently blocked for input. This is
	 primarily to give it a chance to check termination quickly.
	**/
	void WakeUp();

	/**
	 * Returns the number of queued items not yet retrieved.
	 */
	uint64_t Size();

	/**
	 * Statistics about inter-thread communication.
	 */
	struct Stats
		{
		uint64_t num_reads;	//! Number of messages read from the queue.
		uint64_t num_writes;	//! Number of messages written to the queue.
		};

	/**
	 * Returns statistics about the queue's usage.
	 *
	 * @param stats A pointer to a structure that will be filled with
	 * current numbers. */
	void GetStats(Stats* stats);

private:
	static const int NUM_QUEUES = 8;

	pthread_mutex_t mutex[NUM_QUEUES];	// Mutex protected shared accesses.
	pthread_cond_t has_data[NUM_QUEUES];	// Signals when data becomes available
	std::queue<T> messages[NUM_QUEUES];	// Actually holds the queued messages

	int read_ptr;	// Where the next operation will read from
	int write_ptr;	// Where the next operation will write to

	BasicThread* reader;
	BasicThread* writer;

	// Statistics.
	uint64_t num_reads;
	uint64_t num_writes;
};

inline static void safe_lock(pthread_mutex_t* mutex)
	{
	int res = pthread_mutex_lock(mutex);
	if ( res != 0 )
		reporter->FatalErrorWithCore("cannot lock mutex: %d(%s)", res, strerror(res));
	}

inline static void safe_unlock(pthread_mutex_t* mutex)
	{
	if ( pthread_mutex_unlock(mutex) != 0 )
		reporter->FatalErrorWithCore("cannot unlock mutex");
	}

template<typename T>
inline Queue<T>::Queue(BasicThread* arg_reader, BasicThread* arg_writer)
	{
	read_ptr = 0;
	write_ptr = 0;
	num_reads = num_writes = 0;
	reader = arg_reader;
	writer = arg_writer;

	for( int i = 0; i < NUM_QUEUES; ++i )
		{
		if ( pthread_cond_init(&has_data[i], 0) != 0 )
			reporter->FatalError("cannot init queue condition variable");

		if ( pthread_mutex_init(&mutex[i], 0) != 0 )
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

	if ( messages[read_ptr].empty() && ! ((reader && reader->Killed()) || (writer && writer->Killed())) )
		{
		struct timespec ts;
		ts.tv_sec = time(0) + 5;
		ts.tv_nsec = 0;

		pthread_cond_timedwait(&has_data[read_ptr], &mutex[read_ptr], &ts);
		safe_unlock(&mutex[read_ptr]);
		return 0;
		}

	else if ( messages[read_ptr].empty() )
		{
		safe_unlock(&mutex[read_ptr]);
		return 0;
		}

	T data = messages[read_ptr].front();
	messages[read_ptr].pop();

	read_ptr = (read_ptr + 1) % NUM_QUEUES;
	++num_reads;

	safe_unlock(&mutex[old_read_ptr]);

	return data;
	}

template<typename T>
inline void Queue<T>::Put(T data)
	{
	safe_lock(&mutex[write_ptr]);

	int old_write_ptr = write_ptr;

	bool need_signal = messages[write_ptr].empty();

	messages[write_ptr].push(data);

	if ( need_signal )
		pthread_cond_signal(&has_data[write_ptr]);

	write_ptr = (write_ptr + 1) % NUM_QUEUES;
	++num_writes;

	safe_unlock(&mutex[old_write_ptr]);
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

template<typename T>
inline void Queue<T>::GetStats(Stats* stats)
	{
	// To be safe, we look all queues. That's probably unneccessary, but
	// doesn't really hurt.
	for ( int i = 0; i < NUM_QUEUES; i++ )
		safe_lock(&mutex[i]);

	stats->num_reads = num_reads;
	stats->num_writes = num_writes;

	for ( int i = 0; i < NUM_QUEUES; i++ )
		safe_unlock(&mutex[i]);
	}

template<typename T>
inline void Queue<T>::WakeUp()
	{
	for ( int i = 0; i < NUM_QUEUES; i++ )
		{
		safe_lock(&mutex[i]);
		pthread_cond_signal(&has_data[i]);
		safe_unlock(&mutex[i]);
		}
	}

}


#endif

