#pragma once

#include <sys/time.h>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <queue>

#include "zeek/Reporter.h"
#include "zeek/threading/BasicThread.h"

#undef Queue // Defined elsewhere unfortunately.

namespace zeek::threading
	{

/**
 * A thread-safe single-reader single-writer queue.
 *
 * The implementation uses multiple queues and reads/writes in rotary fashion
 * in an attempt to limit contention.
 *
 * All Queue instances must be instantiated by Zeek's main thread.
 *
 * TODO: Unclear how critical performance is for this queue. We could likely
 * optimize it further if helpful.
 */
template <typename T> class Queue
	{
public:
	/**
	 * Constructor.
	 *
	 * reader, writer: The corresponding threads. This is for checking
	 * whether they have terminated so that we can abort I/O operations.
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

	/**
	 * Wake up the reader if it's currently blocked for input. This is
	 * primarily to give it a chance to check termination quickly.
	 */
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
		uint64_t num_reads; //! Number of messages read from the queue.
		uint64_t num_writes; //! Number of messages written to the queue.
		};

	/**
	 * Returns statistics about the queue's usage.
	 *
	 * @param stats A pointer to a structure that will be filled with
	 * current numbers.
	 */
	void GetStats(Stats* stats);

private:
	static const int NUM_QUEUES = 8;

	std::vector<std::unique_lock<std::mutex>> LocksForAllQueues();

	std::mutex mutex[NUM_QUEUES]; // Mutex protected shared accesses.
	std::condition_variable has_data[NUM_QUEUES]; // Signals when data becomes available
	std::queue<T> messages[NUM_QUEUES]; // Actually holds the queued messages

	int read_ptr; // Where the next operation will read from
	int write_ptr; // Where the next operation will write to

	BasicThread* reader;
	BasicThread* writer;

	// Statistics.
	uint64_t num_reads;
	uint64_t num_writes;
	};

inline static std::unique_lock<std::mutex> acquire_lock(std::mutex& m)
	{
	try
		{
		return std::unique_lock<std::mutex>(m);
		}
	catch ( const std::system_error& e )
		{
		reporter->FatalErrorWithCore("cannot lock mutex: %s", e.what());
		// Never gets here.
		throw std::exception();
		}
	}

template <typename T> inline Queue<T>::Queue(BasicThread* arg_reader, BasicThread* arg_writer)
	{
	read_ptr = 0;
	write_ptr = 0;
	num_reads = num_writes = 0;
	reader = arg_reader;
	writer = arg_writer;
	}

template <typename T> inline Queue<T>::~Queue() { }

template <typename T> inline T Queue<T>::Get()
	{
	auto lock = acquire_lock(mutex[read_ptr]);

	int old_read_ptr = read_ptr;

	if ( messages[read_ptr].empty() &&
	     ! ((reader && reader->Killed()) || (writer && writer->Killed())) )
		{
		if ( has_data[read_ptr].wait_for(lock, std::chrono::seconds(5)) == std::cv_status::timeout )
			return nullptr;
		}

	if ( messages[read_ptr].empty() )
		return nullptr;

	T data = messages[read_ptr].front();
	messages[read_ptr].pop();

	read_ptr = (read_ptr + 1) % NUM_QUEUES;
	++num_reads;

	return data;
	}

template <typename T> inline void Queue<T>::Put(T data)
	{
	auto lock = acquire_lock(mutex[write_ptr]);

	int old_write_ptr = write_ptr;

	bool need_signal = messages[write_ptr].empty();

	messages[write_ptr].push(data);

	write_ptr = (write_ptr + 1) % NUM_QUEUES;
	++num_writes;

	if ( need_signal )
		{
		lock.unlock();
		has_data[old_write_ptr].notify_one();
		}
	}

template <typename T> inline bool Queue<T>::Ready()
	{
	auto lock = acquire_lock(mutex[read_ptr]);

	bool ret = (messages[read_ptr].size());

	return ret;
	}

template <typename T> inline std::vector<std::unique_lock<std::mutex>> Queue<T>::LocksForAllQueues()
	{
	std::vector<std::unique_lock<std::mutex>> locks;

	try
		{
		for ( int i = 0; i < NUM_QUEUES; i++ )
			locks.emplace_back(std::unique_lock<std::mutex>(mutex[i]));
		}

	catch ( const std::system_error& e )
		{
		reporter->FatalErrorWithCore("cannot lock all mutexes: %s", e.what());
		// Never gets here.
		throw std::exception();
		}

	return locks;
	}

template <typename T> inline uint64_t Queue<T>::Size()
	{
	// Need to lock all queues.
	auto locks = LocksForAllQueues();

	uint64_t size = 0;

	for ( int i = 0; i < NUM_QUEUES; i++ )
		size += messages[i].size();

	return size;
	}

template <typename T> inline void Queue<T>::GetStats(Stats* stats)
	{
	// To be safe, we look all queues. That's probably unnecessary, but
	// doesn't really hurt.
	auto locks = LocksForAllQueues();

	stats->num_reads = num_reads;
	stats->num_writes = num_writes;
	}

template <typename T> inline void Queue<T>::WakeUp()
	{
	for ( int i = 0; i < NUM_QUEUES; i++ )
		{
		auto lock = acquire_lock(mutex[i]);
		has_data[i].notify_all();
		}
	}

	} // namespace zeek::threading
