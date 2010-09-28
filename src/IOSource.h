// $Id: IOSource.h 6888 2009-08-20 18:23:11Z vern $
//
// Interface for classes providing/consuming data during Bro's main loop.

#ifndef iosource_h
#define iosource_h

#include <list>
#include "Timer.h"

using namespace std;

class IOSource {
public:
	IOSource()	{ idle = closed = false; }
	virtual ~IOSource()	{}

	// Returns true if source has nothing ready to process.
	bool IsIdle() const	{ return idle; }

	// Returns true if more data is to be expected in the future.
	// Otherwise, source may be removed.
	bool IsOpen() const	{ return ! closed; }

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
	bool idle;

	// Derived classed are to set this to true if they have gone dry
	// permanently.
	bool closed;
};

class IOSourceRegistry {
public:
	IOSourceRegistry()	{ call_count = 0; dont_counts = 0; }
	~IOSourceRegistry();

	// If dont_count is true, this source does not contribute to the
	// number of IOSources returned by Size().  The effect is that
	// if all sources but the non-counting ones have gone dry,
	// processing will shut down.
	void Register(IOSource* src, bool dont_count = false);

	// This may block for some time.
	IOSource* FindSoonest(double* ts);

	int Size() const	{ return sources.size() - dont_counts; }

	// Terminate IOSource processing immediately by removing all
	// sources (and therefore returning a Size() of zero).
	void Terminate()	{ RemoveAll(); }

protected:
	// When looking for a source with something to process,
	// every SELECT_FREQUENCY calls we will go ahead and
	// block on a select().
	static const int SELECT_FREQUENCY = 25;

	// Microseconds to wait in an empty select if no source is ready.
	static const int SELECT_TIMEOUT = 50;

	void RemoveAll();

	unsigned int call_count;
	int dont_counts;

	struct Source {
		IOSource* src;
		int fd_read;
		int fd_write;
		int fd_except;
	};

	typedef list<Source*> SourceList;
	SourceList sources;
};

extern IOSourceRegistry io_sources;

#endif
