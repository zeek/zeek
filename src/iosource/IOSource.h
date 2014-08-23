// See the file "COPYING" in the main distribution directory for copyright.

#ifndef IOSOURCE_IOSOURCE_H
#define IOSOURCE_IOSOURCE_H

#include <string>

#include "Timer.h"

namespace iosource {

/**
 * Interface class for components providing/consuming data inside Bro's main loop.
 */
class IOSource {
public:
	IOSource()	{ idle = false; closed = false; }
	virtual ~IOSource()	{}

	// Returns true if source has nothing ready to process.
	bool IsIdle() const	{ return idle; }

	// Returns true if more data is to be expected in the future.
	// Otherwise, source may be removed.
	bool IsOpen() const	{ return ! closed; }

	// XXX
	virtual void Init()	{ }

	// XXX
	virtual void Done()	{ }

	// Returns select'able fds (leaves args untouched if we don't have
	// selectable fds).
	virtual void GetFds(int* read, int* write, int* except) = 0;

	// The following two methods are only called when either IsIdle()
	// returns false or select() on one of the fds indicates that there's
	// data to process.

	// Returns timestamp (in global network time) associated with next
	// data item.  If the source wants the data item to be processed
	// with a local network time, it sets the argument accordingly.
	virtual double NextTimestamp(double* network_time) = 0;

	// Processes and consumes next data item.
	virtual void Process() = 0;

	// Returns tag of timer manager associated with last processed
	// data item, nil for global timer manager.
	virtual TimerMgr::Tag* GetCurrentTag()	{ return 0; }

	// Returns a descriptual tag for debugging.
	virtual const char* Tag() = 0;

protected:
	// Derived classed are to set this to true if they have gone dry
	// temporarily.
	void SetIdle(bool is_idle)	{ idle = is_idle; }

	// Derived classed are to set this to true if they have gone dry
	// temporarily.
	void SetClosed(bool is_closed)	{ closed = is_closed; }

private:
	bool idle;
	bool closed;
};

}

#endif
