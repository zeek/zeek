// See the file "COPYING" in the main distribution directory for copyright.

#ifndef IOSOURCE_IOSOURCE_H
#define IOSOURCE_IOSOURCE_H

extern "C" {
#include <pcap.h>
}

#include <string>
#include "FD_Set.h"
#include "Timer.h"

namespace iosource {

/**
 * Interface class for components providing/consuming data inside Bro's main
 * loop.
 */
class IOSource {
public:
	/**
	 * Constructor.
	 */
	IOSource()	{ idle = false; closed = false; }

	/**
	 * Destructor.
	 */
	virtual ~IOSource()	{}

	/**
	 * Returns true if source has nothing ready to process.
	 */
	bool IsIdle() const	{ return idle; }

	/**
	 * Returns true if more data is to be expected in the future.
	 * Otherwise, source may be removed.
	 */
	bool IsOpen() const	{ return ! closed; }

	/**
	 * Initializes the source. Can be overwritten by derived classes.
	 */
	virtual void Init()	{ }

	/**
	 * Finalizes the source when it's being closed. Can be overwritten by
	 * derived classes.
	 */
	virtual void Done()	{ }

	/**
	 * Returns select'able file descriptors for this source. Leaves the
	 * passed values untouched if not available.
	 *
	 * @param read Pointer to container where to insert a read descriptor.
	 *
	 * @param write Pointer to container where to insert a write descriptor.
	 *
	 * @param except Pointer to container where to insert a except descriptor.
	 */
	virtual void GetFds(FD_Set* read, FD_Set* write, FD_Set* except) = 0;

	/**
	 * Returns the timestamp (in \a global network time) associated with
	 * next data item from this source.  If the source wants the data
	 * item to be processed with a local network time, it sets the
	 * argument accordingly.
	 *
	 * This method will be called only when either IsIdle() returns
	 * false, or select() on one of the fds returned by GetFDs()
	 * indicates that there's data to process.
	 *
	 * Must be overridden by derived classes.
	 *
	 * @param network_time A pointer to store the \a local network time
	 * associated with the next item (as opposed to global network time).
	 *
	 * @return The global network time of the next entry, or a value
	 * smaller than zero if none is available currently.
	 */
	virtual double NextTimestamp(double* network_time) = 0;

	/**
	 * Processes and consumes next data item.
	 *
	 * This method will be called only when either IsIdle() returns
	 * false, or select() on one of the fds returned by GetFDs()
	 * indicates that there's data to process.
	 *
	 * Must be overridden by derived classes.
	 */
	virtual void Process() = 0;

	/**
	 * Returns the tag of the timer manafger associated with the last
	 * procesees data item.
	 *
	 * Can be overridden by derived classes.
	 *
	 * @return The tag, or null for the global timer manager.
	 * 
	 */
	virtual TimerMgr::Tag* GetCurrentTag()	{ return 0; }

	/**
	 * Returns a descriptual tag representing the source for debugging.
	 *
	 * Can be overridden by derived classes.
	 *
	 * @return The debugging name.
	 */
	virtual const char* Tag() = 0;

protected:
	/*
	 * Callback for derived classes to call when they have gone dry
	 * temporarily.
	 *
	 * @param is_idle True if the source is idle currently.
	 */
	void SetIdle(bool is_idle)	{ idle = is_idle; }

	/*
	 * Callback for derived class to call when they have shutdown.
	 *
	 * @param is_closed True if the source is now closed.
	 */
	void SetClosed(bool is_closed)	{ closed = is_closed; }

private:
	bool idle;
	bool closed;
};

}

#endif
